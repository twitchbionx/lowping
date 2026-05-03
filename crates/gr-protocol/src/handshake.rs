//! ECDH session-key derivation for tunnel encryption.
//!
//! Phase 1 design: per-connection ephemeral X25519 key exchange.
//!
//! - Bridge has a long-term X25519 keypair. Public key is published in the
//!   bridge directory.
//! - Client generates a fresh ephemeral X25519 keypair per connection.
//! - Client sends the SYN frame with its ephemeral public key in plaintext
//!   (after the 13-byte header, before the encrypted payload).
//! - Both sides compute `shared = X25519(my_secret, peer_public)`.
//! - Both sides derive the AEAD key:
//!     `aead_key = HKDF-SHA256(shared, info = b"lowping-v1-aead", salt = b"")`
//! - All subsequent frames in this connection use this AEAD key.
//!
//! The AAD covered by the AEAD tag includes the 13-byte header AND, on SYN
//! frames, the client's ephemeral public key bytes — so an attacker can't
//! tamper with either without breaking the tag.

use chacha20poly1305::Key as AeadKey;
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("public key length must be 32, got {0}")]
    BadPubkeyLength(usize),
    #[error("HKDF expand failed (output length error)")]
    HkdfExpand,
}

/// Domain-separation string mixed into the HKDF derivation. Bumping this
/// breaks compatibility with all existing peers; coordinate with PROTO_VERSION.
pub const HKDF_INFO: &[u8] = b"lowping-v1-aead";

/// Derive a 32-byte ChaCha20-Poly1305 key from a raw X25519 shared secret.
pub fn derive_aead_key(shared_secret: &[u8; 32]) -> AeadKey {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF expand of 32 bytes never fails");
    *AeadKey::from_slice(&out)
}

/// Bridge side: given the bridge's long-term secret and a client's ephemeral
/// public key from the SYN frame, derive the AEAD session key for this
/// connection.
pub fn bridge_derive_session_key(
    bridge_secret: &StaticSecret,
    client_ephemeral_pub: &PublicKey,
) -> AeadKey {
    let shared = bridge_secret.diffie_hellman(client_ephemeral_pub);
    derive_aead_key(shared.as_bytes())
}

/// Client side: given the client's ephemeral secret and the bridge's
/// published long-term public key, derive the AEAD session key.
pub fn client_derive_session_key(
    client_ephemeral_secret: &StaticSecret,
    bridge_pub: &PublicKey,
) -> AeadKey {
    let shared = client_ephemeral_secret.diffie_hellman(bridge_pub);
    derive_aead_key(shared.as_bytes())
}

/// Generate a new X25519 keypair (32-byte secret + 32-byte public).
/// Used for both bridge long-term keys and client ephemeral keys.
pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    use rand_core::OsRng;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Parse an X25519 public key from a byte slice (must be exactly 32 bytes).
pub fn pubkey_from_bytes(bytes: &[u8]) -> Result<PublicKey, HandshakeError> {
    if bytes.len() != 32 {
        return Err(HandshakeError::BadPubkeyLength(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(PublicKey::from(arr))
}

/// Parse an X25519 secret from a byte slice (must be exactly 32 bytes).
pub fn secret_from_bytes(bytes: &[u8]) -> Result<StaticSecret, HandshakeError> {
    if bytes.len() != 32 {
        return Err(HandshakeError::BadPubkeyLength(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(StaticSecret::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_key() {
        let (bridge_sk, bridge_pk) = generate_keypair();
        let (client_sk, client_pk) = generate_keypair();
        let bridge_key = bridge_derive_session_key(&bridge_sk, &client_pk);
        let client_key = client_derive_session_key(&client_sk, &bridge_pk);
        assert_eq!(bridge_key.as_slice(), client_key.as_slice());
    }

    #[test]
    fn different_clients_get_different_keys() {
        let (bridge_sk, _) = generate_keypair();
        let (_, client_pk_a) = generate_keypair();
        let (_, client_pk_b) = generate_keypair();
        let key_a = bridge_derive_session_key(&bridge_sk, &client_pk_a);
        let key_b = bridge_derive_session_key(&bridge_sk, &client_pk_b);
        assert_ne!(key_a.as_slice(), key_b.as_slice());
    }

    #[test]
    fn different_bridges_get_different_keys() {
        let (bridge_sk_a, _) = generate_keypair();
        let (bridge_sk_b, _) = generate_keypair();
        let (_, client_pk) = generate_keypair();
        let key_a = bridge_derive_session_key(&bridge_sk_a, &client_pk);
        let key_b = bridge_derive_session_key(&bridge_sk_b, &client_pk);
        assert_ne!(key_a.as_slice(), key_b.as_slice());
    }

    #[test]
    fn pubkey_serializes_to_32_bytes() {
        let (_, pk) = generate_keypair();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 32);
        let back = pubkey_from_bytes(&bytes).unwrap();
        assert_eq!(back.to_bytes(), bytes);
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let err = pubkey_from_bytes(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, HandshakeError::BadPubkeyLength(16)));
    }
}
