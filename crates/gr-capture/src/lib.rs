//! Packet capture / redirect for lowping.
//!
//! Provides a platform-abstracted [`Redirector`] trait. The current
//! implementation uses WinDivert on Windows (Phase 3a). A future native-WFP
//! callout driver (Phase 3b) would also implement this trait, letting
//! gr-client swap the backend without touching tunnel logic.
//!
//! The conceptual model is **destination NAT for selected flows**:
//!
//! 1. Userland adds a [`RedirectRule`] like
//!    `(udp, dst_ip = 1.2.3.4, dst_port = 7777..7800) -> 127.0.0.1:9000`
//! 2. The capture backend hooks the kernel data path
//! 3. For each outbound packet matching a rule:
//!    - rewrite destination to the local target (typically a grclient port)
//!    - record the original destination keyed by source port (NAT table)
//!    - recompute checksums
//! 4. For each inbound packet returning to the local target:
//!    - rewrite source back to the original destination (so the game's socket
//!      sees the response as coming from the real game server)
//!    - recompute checksums

#![cfg_attr(not(windows), allow(dead_code))]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

#[cfg(windows)]
pub mod windivert_backend;

#[cfg(windows)]
pub use windivert_backend::WinDivertCapture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    pub protocol: Protocol,
    pub dst_ip: IpAddr,
    /// Inclusive lower port (single port: set both equal).
    pub dst_port_lo: u16,
    pub dst_port_hi: u16,
    /// Where to redirect to. Typically `127.0.0.1:<grclient-port>`.
    pub redirect_to_ip: IpAddr,
    pub redirect_to_port: u16,
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("driver open failed: {0}")]
    DriverOpen(String),
    #[error("filter syntax error: {0}")]
    FilterSyntax(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend not implemented for this platform")]
    Unsupported,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CaptureError>;

/// Trait every platform backend must satisfy.
///
/// Implementations spawn their own background tasks; `start` returns once
/// they're running. `stop` is best-effort.
pub trait Redirector: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    /// Returns counters for observability.
    fn stats(&self) -> RedirectStats;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RedirectStats {
    pub outbound_redirected: u64,
    pub inbound_rewritten: u64,
    pub dropped_unparseable: u64,
    pub active_flows: u64,
}
