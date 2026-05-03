//! Bridge directory — what `GET /v1/bridges` returns.
//!
//! Clients fetch this list to know what bridges they can connect to. The
//! response is signed by the backend's Ed25519 key so clients verify the
//! list cryptographically (no need to trust the TLS cert alone).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Public-facing bridge entry. Includes everything a client needs to
/// connect to and authenticate the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEntry {
    /// Stable identifier ("dal-1", "fra-2"). Region prefix + ordinal.
    pub id: String,
    /// Human-friendly name shown in the UI ("Dallas", "Frankfurt").
    pub name: String,
    /// Geographic region tag (used for filtering: NA, EU, ASIA, OCE, BR, ME).
    pub region: String,
    /// More specific zone tag (NAC, NAE, NAW, EU-W, EU-C, etc.) used to match
    /// against game server regions.
    pub zone: String,
    /// Where the client connects.
    pub endpoint: SocketAddr,
    /// Bridge's Ed25519 public key, hex-encoded. Client pins this on first add.
    pub pubkey_hex: String,
    /// Game regions this bridge is intended to serve (e.g. ["fortnite-NAC"]).
    /// Clients use this to auto-pick the right bridge per game.
    pub game_zones: Vec<String>,
    /// True if currently accepting clients. Lets us drain a bridge for
    /// maintenance without deleting it.
    pub enabled: bool,
}

/// The full directory document — what the backend returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDirectory {
    pub version: u32,
    pub issued_at: DateTime<Utc>,
    /// After this time, clients should re-fetch.
    pub expires_at: DateTime<Utc>,
    pub bridges: Vec<BridgeEntry>,
}

/// Signed wrapper. `payload_b64` is base64(canonical JSON of BridgeDirectory).
/// `signature_b64` is base64 Ed25519 signature over that exact bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectory {
    pub payload_b64: String,
    pub signature_b64: String,
}

impl SignedDirectory {
    /// Sign a directory with the backend's secret key.
    pub fn sign(directory: &BridgeDirectory, key: &SigningKey) -> Result<Self, serde_json::Error> {
        // Use serde_json's canonical-ish output. For real cross-impl
        // canonicalization we'd want jcs (RFC 8785) but serde_json is
        // deterministic enough for our single-impl case.
        let payload = serde_json::to_vec(directory)?;
        let signature = key.sign(&payload);
        Ok(Self {
            payload_b64: URL_SAFE_NO_PAD.encode(&payload),
            signature_b64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    /// Verify and decode. Used by clients.
    pub fn verify(&self, backend_pubkey: &VerifyingKey) -> Result<BridgeDirectory, VerifyError> {
        let payload = URL_SAFE_NO_PAD
            .decode(self.payload_b64.as_bytes())
            .map_err(|e| VerifyError::Base64(e.to_string()))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature_b64.as_bytes())
            .map_err(|e| VerifyError::Base64(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(VerifyError::BadSignatureLength(sig_bytes.len()));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);
        backend_pubkey
            .verify(&payload, &signature)
            .map_err(|_| VerifyError::BadSignature)?;
        let directory: BridgeDirectory = serde_json::from_slice(&payload)
            .map_err(|e| VerifyError::Json(e.to_string()))?;
        Ok(directory)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("signature wrong length: {0} (expected 64)")]
    BadSignatureLength(usize),
    #[error("signature verification failed")]
    BadSignature,
    #[error("json decode error: {0}")]
    Json(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn sample_directory() -> BridgeDirectory {
        BridgeDirectory {
            version: 1,
            issued_at: "2026-05-03T12:00:00Z".parse().unwrap(),
            expires_at: "2026-05-03T12:30:00Z".parse().unwrap(),
            bridges: vec![BridgeEntry {
                id: "dal-1".into(),
                name: "Dallas".into(),
                region: "NA".into(),
                zone: "NAC".into(),
                endpoint: "203.0.113.1:51820".parse().unwrap(),
                pubkey_hex: "abcd".repeat(8),
                game_zones: vec!["fortnite-NAC".into(), "valorant-NAC".into()],
                enabled: true,
            }],
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let dir = sample_directory();
        let signed = SignedDirectory::sign(&dir, &sk).unwrap();
        let back = signed.verify(&pk).unwrap();
        assert_eq!(back.bridges.len(), 1);
        assert_eq!(back.bridges[0].id, "dal-1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let dir = sample_directory();
        let mut signed = SignedDirectory::sign(&dir, &sk).unwrap();
        // Flip a character in the payload — invalidates signature
        let mut chars: Vec<char> = signed.payload_b64.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        signed.payload_b64 = chars.into_iter().collect();
        let err = signed.verify(&pk).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature | VerifyError::Base64(_) | VerifyError::Json(_)));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let dir = sample_directory();
        let signed = SignedDirectory::sign(&dir, &sk1).unwrap();
        let err = signed.verify(&sk2.verifying_key()).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature));
    }
}
