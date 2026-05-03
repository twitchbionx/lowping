//! Shared types between all lowping crates.
//!
//! This crate intentionally has minimal dependencies — anything heavyweight
//! lives in the crate that uses it (gr-client, gr-bridge), not here.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

/// Configuration for a single bridge a client knows about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Human-readable name shown in the UI ("Frankfurt", "my-vps").
    pub name: String,
    /// Where to connect on the wire.
    pub endpoint: SocketAddr,
    /// Bridge's Ed25519 public key, hex-encoded. We pin this and refuse to
    /// connect if the bridge presents a different key (TOFU on first add).
    pub bridge_pubkey_hex: String,
    /// Our Ed25519 secret key for proving identity to this bridge, hex-encoded.
    /// Each bridge sees a different identity if you want to.
    pub client_seckey_hex: String,
    /// Optional region tag for selection heuristics.
    pub region: Option<String>,
    /// Whether this bridge is currently enabled for selection.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

/// Top-level client config — what `grclient` reads at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub bridges: Vec<BridgeConfig>,
    /// FEC redundancy ratio. 0 = disabled. Typical: 0.2-0.5
    #[serde(default)]
    pub fec_ratio: f32,
    /// Send each packet via N bridges simultaneously. 1 = single-path (default).
    #[serde(default = "default_paths")]
    pub paths: u8,
    /// Local IPC pipe path the UI connects to.
    #[serde(default = "default_pipe")]
    pub ipc_pipe: String,
}

fn default_paths() -> u8 { 1 }
fn default_pipe() -> String { r"\\.\pipe\lowping".to_string() }

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bridges: Vec::new(),
            fec_ratio: 0.0,
            paths: 1,
            ipc_pipe: default_pipe(),
        }
    }
}

/// Bridge config — what `grbridge` reads at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeServerConfig {
    /// UDP socket to bind.
    pub listen: SocketAddr,
    /// This bridge's Ed25519 secret key, hex-encoded.
    pub bridge_seckey_hex: String,
    /// Allowed client public keys (Ed25519 hex). Empty = no auth (don't do this).
    pub allowed_client_pubkeys: Vec<String>,
    /// Optional Prometheus metrics endpoint.
    pub metrics_listen: Option<SocketAddr>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

impl ClientConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

impl BridgeServerConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}
