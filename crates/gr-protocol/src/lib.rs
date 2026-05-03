//! lowping wire protocol.
//!
//! All bytes flowing between client and bridge are wrapped in [`Frame`].
//! A frame carries one chunk of work — either a control message (CONNECT,
//! FIN), a data payload (game packet), or an FEC parity packet that helps
//! the receiver recover a lost data packet.
//!
//! Frame layout (network byte order, all integers big-endian):
//!
//! ```text
//!  0      1                       5                              13
//!  ┌──────┬───────────────────────┬──────────────────────────────┐
//!  │ ver  │   connection_id (32)  │       sequence (64)          │
//!  │  +   │                       │                              │
//!  │ flag │                       │                              │
//!  └──────┴───────────────────────┴──────────────────────────────┘
//!  13                                                  N            N+16
//!  ┌──────────────────────────────────────────────────┬───────────┐
//!  │             ciphertext                            │  tag (16) │
//!  └──────────────────────────────────────────────────┴───────────┘
//! ```
//!
//! Header is 13 bytes plaintext (used for routing / dedup before decrypt) and
//! is also the AEAD's associated data so tampering with it fails authentication.
//!
//! The 12-byte AEAD nonce is **not transmitted** — it's derived from
//! `(connection_id, sequence)` which the receiver already has from the header.
//! That saves 12 bytes per packet over including the nonce on wire. ChaCha20-
//! Poly1305 takes a 12-byte nonce, and `connection_id || sequence` is exactly
//! 12 bytes of unique-per-message material under one session key — so no
//! nonce-reuse risk as long as a sender never reuses a (cid, seq) pair.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use thiserror::Error;

pub mod fec;
pub mod handshake;
pub mod license;

pub const HEADER_LEN: usize = 13;
/// AEAD nonce length — derived, not transmitted.
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Smallest valid frame: header + tag (empty payload still has the AEAD tag).
pub const MIN_FRAME_LEN: usize = HEADER_LEN + TAG_LEN;

/// Maximum payload after AEAD overhead. Tuned to fit one packet inside 1280
/// bytes (IPv6 minimum MTU) after IP+UDP headers (40+8 for IPv6).
/// 1280 - 40 - 8 - HEADER_LEN - TAG_LEN = 1203. Round down.
pub const MAX_PAYLOAD_LEN: usize = 1200;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame too short: got {got} bytes, need at least {need}")]
    Truncated { got: usize, need: usize },

    #[error("unknown protocol version {0}")]
    UnknownVersion(u8),

    #[error("payload exceeds maximum ({0} > {max})", max = MAX_PAYLOAD_LEN)]
    PayloadTooLarge(usize),

    #[error("AEAD authentication failed (wrong key, tampered, or replayed)")]
    AeadFailed,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Current wire protocol version. Bumping this breaks compatibility.
pub const PROTO_VERSION: u8 = 1;

bitflags::bitflags! {
    /// Per-frame flags packed into the high bits of the first byte.
    /// Low 4 bits are reserved for the version field.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 {
        /// This frame is a Reed-Solomon parity packet, not data.
        const FEC_PARITY = 0b0001_0000;
        /// First frame of a new connection — payload contains a CONNECT message.
        const SYN        = 0b0010_0000;
        /// Last frame of this connection — sender will not send more.
        const FIN        = 0b0100_0000;
        /// Duplicate copy sent over alternate path; receiver dedups by (cid, seq).
        const REDUNDANT  = 0b1000_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: Flags,
    pub connection_id: u32,
    pub sequence: u64,
}

impl Header {
    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = (self.version & 0x0F) | self.flags.bits();
        out[1..5].copy_from_slice(&self.connection_id.to_be_bytes());
        out[5..13].copy_from_slice(&self.sequence.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated { got: buf.len(), need: HEADER_LEN });
        }
        let v = buf[0] & 0x0F;
        if v != PROTO_VERSION {
            return Err(ProtocolError::UnknownVersion(v));
        }
        let flags = Flags::from_bits_truncate(buf[0] & 0xF0);
        let connection_id = u32::from_be_bytes(buf[1..5].try_into().unwrap());
        let sequence = u64::from_be_bytes(buf[5..13].try_into().unwrap());
        Ok(Header { version: v, flags, connection_id, sequence })
    }
}

/// Derive the AEAD nonce from connection_id + sequence.
/// Format: 4 bytes connection_id || 8 bytes sequence (12 bytes total).
/// This guarantees no nonce reuse under a fixed session key as long as
/// (connection_id, sequence) is unique per direction.
fn derive_nonce(connection_id: u32, sequence: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0..4].copy_from_slice(&connection_id.to_be_bytes());
    n[4..12].copy_from_slice(&sequence.to_be_bytes());
    n
}

/// Encrypt `payload` and produce the on-wire bytes (header + ciphertext + tag).
/// `aad` is the header bytes — they're authenticated but not encrypted.
pub fn encrypt_frame(
    key: &Key,
    header: &Header,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge(payload.len()));
    }
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = derive_nonce(header.connection_id, header.sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut header_bytes = [0u8; HEADER_LEN];
    header.encode(&mut header_bytes);

    let ct = cipher
        .encrypt(nonce, Payload { msg: payload, aad: &header_bytes })
        .map_err(|_| ProtocolError::AeadFailed)?;

    // Wire format: header || ciphertext (which already includes 16B tag at end)
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse and decrypt a frame. Returns the header and decrypted payload.
pub fn decrypt_frame(key: &Key, wire: &[u8]) -> Result<(Header, Vec<u8>)> {
    if wire.len() < MIN_FRAME_LEN {
        return Err(ProtocolError::Truncated { got: wire.len(), need: MIN_FRAME_LEN });
    }
    let header = Header::decode(&wire[..HEADER_LEN])?;
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = derive_nonce(header.connection_id, header.sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let pt = cipher
        .decrypt(nonce, Payload { msg: &wire[HEADER_LEN..], aad: &wire[..HEADER_LEN] })
        .map_err(|_| ProtocolError::AeadFailed)?;
    Ok((header, pt))
}

// ---------- SYN frame format (handshake) ----------

/// X25519 public key length (32 bytes), as it appears on the wire in SYN frames.
pub const PUBKEY_LEN: usize = 32;
/// SYN frames carry the client's ephemeral X25519 pubkey in plaintext between
/// the header and the ciphertext.
pub const SYN_HEADER_LEN: usize = HEADER_LEN + PUBKEY_LEN;
pub const MIN_SYN_FRAME_LEN: usize = SYN_HEADER_LEN + TAG_LEN;

/// Encrypt a SYN frame: prepends the client's ephemeral pubkey in plaintext,
/// AEADs the payload with `aead_key`, AAD covers (header || pubkey).
pub fn encrypt_syn_frame(
    aead_key: &Key,
    header: &Header,
    client_pubkey: &[u8; PUBKEY_LEN],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge(payload.len()));
    }
    if !header.flags.contains(Flags::SYN) {
        // Caller error — should always have SYN flag if using this function.
        // We still produce output but tests should catch this.
    }
    let mut header_bytes = [0u8; HEADER_LEN];
    header.encode(&mut header_bytes);

    let mut aad = Vec::with_capacity(SYN_HEADER_LEN);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(client_pubkey);

    let cipher = ChaCha20Poly1305::new(aead_key);
    let nonce_bytes = derive_nonce(header.connection_id, header.sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: payload, aad: &aad })
        .map_err(|_| ProtocolError::AeadFailed)?;

    let mut out = Vec::with_capacity(SYN_HEADER_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse the plaintext front of a SYN frame: returns header + client pubkey.
/// Caller then derives session key via ECDH and calls [`decrypt_syn_payload`].
pub fn parse_syn_front(wire: &[u8]) -> Result<(Header, [u8; PUBKEY_LEN])> {
    if wire.len() < MIN_SYN_FRAME_LEN {
        return Err(ProtocolError::Truncated {
            got: wire.len(),
            need: MIN_SYN_FRAME_LEN,
        });
    }
    let header = Header::decode(&wire[..HEADER_LEN])?;
    let mut pk = [0u8; PUBKEY_LEN];
    pk.copy_from_slice(&wire[HEADER_LEN..SYN_HEADER_LEN]);
    Ok((header, pk))
}

/// Decrypt a SYN frame's encrypted payload using the derived session key.
pub fn decrypt_syn_payload(aead_key: &Key, wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < MIN_SYN_FRAME_LEN {
        return Err(ProtocolError::Truncated {
            got: wire.len(),
            need: MIN_SYN_FRAME_LEN,
        });
    }
    let cipher = ChaCha20Poly1305::new(aead_key);
    let header = Header::decode(&wire[..HEADER_LEN])?;
    let nonce_bytes = derive_nonce(header.connection_id, header.sequence);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &wire[SYN_HEADER_LEN..],
                aad: &wire[..SYN_HEADER_LEN],
            },
        )
        .map_err(|_| ProtocolError::AeadFailed)
}

/// CONNECT control message — sent in the SYN frame's encrypted payload.
/// Tells the bridge what real destination to open a socket to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol: TransportProtocol,
    pub dest_ip: std::net::IpAddr,
    pub dest_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportProtocol {
    Tcp = 1,
    Udp = 2,
}

impl TransportProtocol {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            _ => None,
        }
    }
}

impl ConnectRequest {
    /// Wire format inside encrypted payload:
    /// `[1B proto] [1B addrlen=4|16] [addrlen B addr] [2B port BE]`
    pub fn encode(&self) -> Vec<u8> {
        let (addr_bytes, addr_len): (Vec<u8>, u8) = match self.dest_ip {
            std::net::IpAddr::V4(v4) => (v4.octets().to_vec(), 4),
            std::net::IpAddr::V6(v6) => (v6.octets().to_vec(), 16),
        };
        let mut out = Vec::with_capacity(1 + 1 + addr_len as usize + 2);
        out.push(self.protocol as u8);
        out.push(addr_len);
        out.extend_from_slice(&addr_bytes);
        out.extend_from_slice(&self.dest_port.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(ProtocolError::Truncated { got: buf.len(), need: 4 });
        }
        let protocol = TransportProtocol::from_byte(buf[0])
            .ok_or(ProtocolError::Truncated { got: buf.len(), need: 4 })?;
        let addr_len = buf[1] as usize;
        if !(addr_len == 4 || addr_len == 16) {
            return Err(ProtocolError::Truncated { got: buf.len(), need: 4 + addr_len });
        }
        let need = 2 + addr_len + 2;
        if buf.len() < need {
            return Err(ProtocolError::Truncated { got: buf.len(), need });
        }
        let dest_ip = if addr_len == 4 {
            let mut a = [0u8; 4];
            a.copy_from_slice(&buf[2..6]);
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(a))
        } else {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[2..18]);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(a))
        };
        let port_off = 2 + addr_len;
        let dest_port = u16::from_be_bytes(buf[port_off..port_off + 2].try_into().unwrap());
        Ok(ConnectRequest { protocol, dest_ip, dest_port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        // Deterministic test key. NEVER reuse in production.
        *Key::from_slice(&[0xAA; 32])
    }

    #[test]
    fn roundtrip_data_frame() {
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::empty(),
            connection_id: 0xCAFEBABE,
            sequence: 42,
        };
        let payload = b"hello world from a game packet";
        let wire = encrypt_frame(&test_key(), &header, payload).unwrap();
        let (h2, p2) = decrypt_frame(&test_key(), &wire).unwrap();
        assert_eq!(header, h2);
        assert_eq!(payload.as_slice(), p2.as_slice());
    }

    #[test]
    fn roundtrip_syn_with_connect() {
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::SYN,
            connection_id: 0x12345678,
            sequence: 0,
        };
        let cr = ConnectRequest {
            protocol: TransportProtocol::Udp,
            dest_ip: "203.0.113.45".parse().unwrap(),
            dest_port: 27015,
        };
        let payload = cr.encode();
        let wire = encrypt_frame(&test_key(), &header, &payload).unwrap();
        let (h2, p2) = decrypt_frame(&test_key(), &wire).unwrap();
        assert_eq!(header, h2);
        assert!(h2.flags.contains(Flags::SYN));
        let cr2 = ConnectRequest::decode(&p2).unwrap();
        assert_eq!(cr, cr2);
    }

    #[test]
    fn tampered_frame_rejected() {
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::empty(),
            connection_id: 1,
            sequence: 1,
        };
        let mut wire = encrypt_frame(&test_key(), &header, b"data").unwrap();
        // Flip a byte in the ciphertext
        let last = wire.len() - 5;
        wire[last] ^= 0x01;
        assert!(matches!(
            decrypt_frame(&test_key(), &wire),
            Err(ProtocolError::AeadFailed)
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::empty(),
            connection_id: 1,
            sequence: 1,
        };
        let wire = encrypt_frame(&test_key(), &header, b"data").unwrap();
        let bad_key = *Key::from_slice(&[0xBB; 32]);
        assert!(matches!(
            decrypt_frame(&bad_key, &wire),
            Err(ProtocolError::AeadFailed)
        ));
    }

    #[test]
    fn ipv6_connect_roundtrip() {
        let cr = ConnectRequest {
            protocol: TransportProtocol::Tcp,
            dest_ip: "2001:db8::1".parse().unwrap(),
            dest_port: 443,
        };
        let bytes = cr.encode();
        let cr2 = ConnectRequest::decode(&bytes).unwrap();
        assert_eq!(cr, cr2);
    }

    #[test]
    fn unknown_version_rejected() {
        // Version field is the low 4 bits of byte 0, so any value 0-15 is a
        // valid encoding. PROTO_VERSION == 1, so version 7 is "unknown".
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes[0] = 7;
        let err = Header::decode(&header_bytes).unwrap_err();
        assert!(matches!(err, ProtocolError::UnknownVersion(7)));
    }

    #[test]
    fn syn_frame_roundtrip_via_ecdh() {
        use crate::handshake;
        let (bridge_sk, bridge_pk) = handshake::generate_keypair();
        let (client_sk, client_pk) = handshake::generate_keypair();

        // Client side: derive session key, encrypt SYN.
        let client_aead = handshake::client_derive_session_key(&client_sk, &bridge_pk);
        let client_pk_bytes = client_pk.to_bytes();
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::SYN,
            connection_id: 0xFEEDC0DE,
            sequence: 0,
        };
        let inner_payload = b"license_token_bytes_then_connect_request";
        let wire = encrypt_syn_frame(&client_aead, &header, &client_pk_bytes, inner_payload).unwrap();

        // Bridge side: parse front, derive session key, decrypt rest.
        let (parsed_header, peer_pk_bytes) = parse_syn_front(&wire).unwrap();
        assert_eq!(parsed_header, header);
        let peer_pk = handshake::pubkey_from_bytes(&peer_pk_bytes).unwrap();
        let bridge_aead = handshake::bridge_derive_session_key(&bridge_sk, &peer_pk);
        assert_eq!(bridge_aead.as_slice(), client_aead.as_slice());
        let decrypted = decrypt_syn_payload(&bridge_aead, &wire).unwrap();
        assert_eq!(decrypted.as_slice(), inner_payload);
    }

    #[test]
    fn syn_frame_with_wrong_bridge_key_fails() {
        use crate::handshake;
        let (_, bridge_pk) = handshake::generate_keypair();
        let (wrong_bridge_sk, _) = handshake::generate_keypair();
        let (client_sk, client_pk) = handshake::generate_keypair();
        let client_aead = handshake::client_derive_session_key(&client_sk, &bridge_pk);
        let client_pk_bytes = client_pk.to_bytes();
        let header = Header {
            version: PROTO_VERSION, flags: Flags::SYN, connection_id: 1, sequence: 0,
        };
        let wire = encrypt_syn_frame(&client_aead, &header, &client_pk_bytes, b"hello").unwrap();
        let (_, peer_pk_bytes) = parse_syn_front(&wire).unwrap();
        let peer_pk = handshake::pubkey_from_bytes(&peer_pk_bytes).unwrap();
        let bridge_aead = handshake::bridge_derive_session_key(&wrong_bridge_sk, &peer_pk);
        let result = decrypt_syn_payload(&bridge_aead, &wire);
        assert!(matches!(result, Err(ProtocolError::AeadFailed)));
    }

    #[test]
    fn syn_frame_truncated_rejected() {
        // Wire is shorter than even SYN_HEADER_LEN
        let too_short = vec![0u8; HEADER_LEN + 10];
        assert!(matches!(
            parse_syn_front(&too_short),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn header_flag_bits_dont_collide_with_version() {
        // Version field is low 4 bits; flags are high 4 bits.
        // Verify they don't overlap in the encoding.
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::SYN | Flags::FEC_PARITY,
            connection_id: 0,
            sequence: 0,
        };
        let mut buf = [0u8; HEADER_LEN];
        header.encode(&mut buf);
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded.flags, Flags::SYN | Flags::FEC_PARITY);
        assert_eq!(decoded.version, PROTO_VERSION);
    }
}
