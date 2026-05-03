//! Per-tunnel session state.
//!
//! A "session" is one (client_socket_addr, connection_id) pair. The struct
//! holds the WRITE half of the dest socket (for forward_data); the READ half
//! is moved into the per-session drain task so the two paths don't contend
//! on a single mutex.

use chacha20poly1305::Key as AeadKey;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub client_addr: SocketAddr,
    pub connection_id: u32,
}

/// Write side of the destination socket — what `forward_data` writes user
/// bytes to. UDP sockets are connected so we can `send` without an addr.
pub enum DestWriter {
    Tcp(OwnedWriteHalf),
    Udp(Arc<UdpSocket>),
}

pub struct Session {
    pub aead_key: AeadKey,
    /// Per-direction sequence counter for outgoing (bridge → client) frames.
    pub tx_sequence: u64,
    pub last_active: Instant,
    pub dest_writer: DestWriter,
}

impl Session {
    pub fn new(aead_key: AeadKey, dest_writer: DestWriter) -> Self {
        Self {
            aead_key,
            tx_sequence: 0,
            last_active: Instant::now(),
            dest_writer,
        }
    }
}
