//! Bridge runtime configuration.

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use x25519_dalek::StaticSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// UDP socket to bind. e.g. "0.0.0.0:51820"
    pub listen: SocketAddr,
    /// Bridge's long-term X25519 secret key (32 bytes hex).
    /// Generate with `grbridge gen-key`.
    pub bridge_x25519_seckey_hex: String,
    /// Backend's Ed25519 public key (32 bytes hex). Bridge uses this to
    /// verify license tokens presented by clients.
    pub backend_ed25519_pubkey_hex: String,
    /// If true, accept any signed token (for solo / dev use).
    /// If false, require token's `scope` field to have bit 0 set ("any-bridge").
    #[serde(default)]
    pub allow_any_scope: bool,
    /// Maximum simultaneous active sessions. Refuse new SYNs above this.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Per-session idle timeout in seconds (drop sessions with no traffic).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Optional Prometheus metrics endpoint.
    pub metrics_listen: Option<SocketAddr>,
}

fn default_max_sessions() -> usize { 10_000 }
fn default_idle_timeout() -> u64 { 300 }

impl BridgeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn parsed_x25519_secret(&self) -> Result<StaticSecret> {
        let bytes = hex::decode(&self.bridge_x25519_seckey_hex)?;
        gr_protocol::handshake::secret_from_bytes(&bytes).map_err(Into::into)
    }

    pub fn parsed_backend_pubkey(&self) -> Result<VerifyingKey> {
        let bytes = hex::decode(&self.backend_ed25519_pubkey_hex)?;
        if bytes.len() != 32 {
            anyhow::bail!("backend_ed25519_pubkey_hex must be 32 bytes (64 hex chars)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(VerifyingKey::from_bytes(&arr)?)
    }
}
