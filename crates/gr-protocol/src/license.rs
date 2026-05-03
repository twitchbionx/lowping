//! License tokens.
//!
//! Compact Ed25519-signed access tokens. The backend issues them, bridges
//! verify them stateless (no API call to backend). Any bridge can verify any
//! token issued by any backend whose Ed25519 public key it has in its config.
//!
//! Wire format (88 bytes total, ASCII representation = 120-char base64-url):
//!
//! ```text
//!  0      4              12              20         24                88
//!  ┌──────┬──────────────┬──────────────┬──────────┬──────────────────┐
//!  │ uid  │  issued_at   │  expires_at  │  scope   │   signature      │
//!  │ (4B) │   (8B i64)   │   (8B i64)   │  (4B)    │     (64B)        │
//!  └──────┴──────────────┴──────────────┴──────────┴──────────────────┘
//!  └──────── 24 bytes signed payload ─────────────┘
//! ```
//!
//! All integers big-endian. Timestamps are Unix seconds.
//!
//! `scope` is a bitfield reserved for future feature gating (e.g. "premium
//! routes", "multi-path enabled"). For MVP we just set bit 0 = "any bridge".

#![allow(clippy::needless_range_loop)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

pub const PAYLOAD_LEN: usize = 4 + 8 + 8 + 4; // 24
pub const SIG_LEN: usize = 64;
pub const TOKEN_LEN: usize = PAYLOAD_LEN + SIG_LEN; // 88

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("token wrong length: got {0} bytes, need {expected}", expected = TOKEN_LEN)]
    WrongLength(usize),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("invalid signature")]
    BadSignature,
    #[error("token expired at {expires_at} (now {now})")]
    Expired { expires_at: i64, now: i64 },
    #[error("token not yet valid: issued_at {issued_at} > now {now}")]
    NotYetValid { issued_at: i64, now: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicensePayload {
    pub user_id: u32,
    pub issued_at: i64,
    pub expires_at: i64,
    pub scope: u32,
}

impl LicensePayload {
    pub fn encode(&self) -> [u8; PAYLOAD_LEN] {
        let mut out = [0u8; PAYLOAD_LEN];
        out[0..4].copy_from_slice(&self.user_id.to_be_bytes());
        out[4..12].copy_from_slice(&self.issued_at.to_be_bytes());
        out[12..20].copy_from_slice(&self.expires_at.to_be_bytes());
        out[20..24].copy_from_slice(&self.scope.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Self {
        debug_assert!(buf.len() >= PAYLOAD_LEN);
        Self {
            user_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            issued_at: i64::from_be_bytes(buf[4..12].try_into().unwrap()),
            expires_at: i64::from_be_bytes(buf[12..20].try_into().unwrap()),
            scope: u32::from_be_bytes(buf[20..24].try_into().unwrap()),
        }
    }
}

/// A signed license token. Issue with [`Self::sign`], verify with [`Self::verify`].
#[derive(Debug, Clone)]
pub struct LicenseToken {
    pub payload: LicensePayload,
    pub signature: Signature,
}

impl LicenseToken {
    /// Sign a payload with the backend's secret key, producing an issuable token.
    pub fn sign(payload: LicensePayload, key: &SigningKey) -> Self {
        let payload_bytes = payload.encode();
        let signature = key.sign(&payload_bytes);
        Self { payload, signature }
    }

    /// Verify a token's signature and that it's currently within its validity
    /// window (issued_at <= now < expires_at).
    pub fn verify(&self, backend_pubkey: &VerifyingKey, now_unix: i64) -> Result<(), LicenseError> {
        let payload_bytes = self.payload.encode();
        backend_pubkey
            .verify(&payload_bytes, &self.signature)
            .map_err(|_| LicenseError::BadSignature)?;
        if now_unix < self.payload.issued_at {
            return Err(LicenseError::NotYetValid {
                issued_at: self.payload.issued_at,
                now: now_unix,
            });
        }
        if now_unix >= self.payload.expires_at {
            return Err(LicenseError::Expired {
                expires_at: self.payload.expires_at,
                now: now_unix,
            });
        }
        Ok(())
    }

    /// Encode to raw bytes (88 bytes).
    pub fn to_bytes(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0u8; TOKEN_LEN];
        out[..PAYLOAD_LEN].copy_from_slice(&self.payload.encode());
        out[PAYLOAD_LEN..].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Decode from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LicenseError> {
        if bytes.len() != TOKEN_LEN {
            return Err(LicenseError::WrongLength(bytes.len()));
        }
        let payload = LicensePayload::decode(&bytes[..PAYLOAD_LEN]);
        let mut sig_bytes = [0u8; SIG_LEN];
        sig_bytes.copy_from_slice(&bytes[PAYLOAD_LEN..]);
        Ok(Self { payload, signature: Signature::from_bytes(&sig_bytes) })
    }

    /// Encode to a URL-safe base64 string suitable for config files / HTTP headers.
    pub fn to_string_b64(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    /// Decode from a URL-safe base64 string.
    pub fn from_string_b64(s: &str) -> Result<Self, LicenseError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| LicenseError::Base64(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn fresh_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    #[test]
    fn signed_token_verifies() {
        let (sk, pk) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 42,
            issued_at: 1_000_000,
            expires_at: 2_000_000,
            scope: 1,
        };
        let token = LicenseToken::sign(payload, &sk);
        token.verify(&pk, 1_500_000).unwrap();
    }

    #[test]
    fn expired_token_rejected() {
        let (sk, pk) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 1, issued_at: 100, expires_at: 200, scope: 0,
        };
        let token = LicenseToken::sign(payload, &sk);
        let err = token.verify(&pk, 300).unwrap_err();
        assert!(matches!(err, LicenseError::Expired { .. }));
    }

    #[test]
    fn not_yet_valid_rejected() {
        let (sk, pk) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 1, issued_at: 1000, expires_at: 2000, scope: 0,
        };
        let token = LicenseToken::sign(payload, &sk);
        let err = token.verify(&pk, 500).unwrap_err();
        assert!(matches!(err, LicenseError::NotYetValid { .. }));
    }

    #[test]
    fn signature_from_other_key_rejected() {
        let (sk1, _pk1) = fresh_keypair();
        let (_sk2, pk2) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 1, issued_at: 0, expires_at: i64::MAX, scope: 0,
        };
        let token = LicenseToken::sign(payload, &sk1);
        // Verify with a different backend's pubkey
        let err = token.verify(&pk2, 100).unwrap_err();
        assert!(matches!(err, LicenseError::BadSignature));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sk, pk) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 1, issued_at: 0, expires_at: i64::MAX, scope: 0,
        };
        let token = LicenseToken::sign(payload, &sk);
        let mut bytes = token.to_bytes();
        // Flip one bit in the user_id
        bytes[0] ^= 0x01;
        let tampered = LicenseToken::from_bytes(&bytes).unwrap();
        let err = tampered.verify(&pk, 100).unwrap_err();
        assert!(matches!(err, LicenseError::BadSignature));
    }

    #[test]
    fn base64_roundtrip() {
        let (sk, pk) = fresh_keypair();
        let payload = LicensePayload {
            user_id: 0xCAFEBABE, issued_at: 1, expires_at: 9999999, scope: 0xDEADBEEF,
        };
        let token = LicenseToken::sign(payload, &sk);
        let s = token.to_string_b64();
        // URL-safe base64 of 88 bytes = ceil(88 * 4 / 3) = 118 chars (no padding)
        assert_eq!(s.len(), 118);
        let back = LicenseToken::from_string_b64(&s).unwrap();
        assert_eq!(back.payload, token.payload);
        back.verify(&pk, 1000).unwrap();
    }
}
