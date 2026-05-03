//! Backend in-memory + on-disk state.
//!
//! For the MVP everything lives in a single TOML file on disk (`backend.toml`).
//! When we need real persistence (per-user accounts, revocations) we'll switch
//! to SQLite. Today's needs are tiny.

use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::net::SocketAddr;

use crate::directory::BridgeEntry;

/// Persistent on-disk config. Operator edits this; backend re-reads on SIGHUP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// HTTP listen address.
    pub listen: SocketAddr,
    /// Backend's Ed25519 secret key (hex). Used to sign tokens AND directories.
    /// Generate once with `openssl rand -hex 32`.
    pub backend_seckey_hex: String,
    /// All bridges we know about. Operator adds/removes entries here.
    pub bridges: Vec<BridgeEntry>,
    /// How long license tokens are valid (seconds). Default: 7 days.
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
    /// How long bridge directories are valid (seconds) before clients re-fetch.
    /// Default: 30 minutes.
    #[serde(default = "default_directory_ttl")]
    pub directory_ttl_secs: u64,
}

fn default_token_ttl() -> u64 { 7 * 24 * 60 * 60 }
fn default_directory_ttl() -> u64 { 30 * 60 }

impl BackendConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}

/// Derived runtime state. Holds the parsed signing key + atomic counters.
pub struct AppState {
    pub config: RwLock<BackendConfig>,
    pub config_path: PathBuf,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// Monotonically increasing counter for issued user_ids.
    /// Persisted to disk separately (not in TOML) so we don't lose it on restart.
    pub next_user_id: parking_lot::Mutex<u32>,
}

impl AppState {
    pub fn new(config: BackendConfig, config_path: PathBuf) -> anyhow::Result<Arc<Self>> {
        let key_bytes = hex::decode(&config.backend_seckey_hex)?;
        if key_bytes.len() != 32 {
            anyhow::bail!("backend_seckey_hex must be 32 bytes (64 hex chars)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&arr);
        let verifying_key = signing_key.verifying_key();
        Ok(Arc::new(Self {
            config: RwLock::new(config),
            config_path,
            signing_key,
            verifying_key,
            // For MVP just start at 1; production wants a persisted counter
            next_user_id: parking_lot::Mutex::new(1),
        }))
    }

    pub fn issue_user_id(&self) -> u32 {
        let mut guard = self.next_user_id.lock();
        let id = *guard;
        *guard = guard.checked_add(1).expect("user_id overflow — congratulations");
        id
    }
}
