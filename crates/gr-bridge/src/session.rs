//! Per-tunnel session state.
//!
//! A "session" is one (client_socket_addr, connection_id) pair. It owns:
//!  - the AEAD session key (derived once at SYN)
//!  - the destination socket (TCP stream or UDP socket)
//!  - sequence counters (to drop replays / out-of-window packets)
//!  - last-activity timestamp (for idle timeout)
//!
//! The bridge maintains a `HashMap<SessionKey, Session>` keyed by
//! (client_addr, connection_id). The packet receiver path looks up the
//! session for each incoming frame.

use chacha20poly1305::Key as AeadKey;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// Composite key identifying a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub client_addr: SocketAddr,
    pub connection_id: u32,
}

/// Channel a session uses to receive bytes that should be sent back to the
/// client. The server task encrypts + frames them and writes to the UDP
/// socket. We separate this from the destination socket so the session task
/// doesn't have to share the listening socket directly (cleaner ownership).
pub type DownstreamTx = mpsc::UnboundedSender<DownstreamPacket>;

/// One chunk to encrypt and send back to a client.
pub struct DownstreamPacket {
    pub session_key: SessionKey,
    /// Plaintext payload (will be encrypted before send).
    pub payload: Vec<u8>,
}

pub struct Session {
    pub key: SessionKey,
    pub aead_key: AeadKey,
    /// Per-direction sequence counter. Outgoing frames (bridge → client) use
    /// this; we increment after each send.
    pub tx_sequence: u64,
    pub last_active: Instant,
    /// Destination socket. Phase 1 supports both TCP and UDP.
    pub dest: DestSocket,
}

pub enum DestSocket {
    /// For TCP destinations we splice the ordered byte stream. Reads and
    /// writes go through this single socket.
    Tcp(TcpStream),
    /// For UDP destinations we use a connected UDP socket so we can
    /// `send`/`recv` without supplying the address each time.
    Udp(UdpSocket),
}

impl Session {
    pub fn new(key: SessionKey, aead_key: AeadKey, dest: DestSocket) -> Self {
        Self {
            key,
            aead_key,
            tx_sequence: 0,
            last_active: Instant::now(),
            dest,
        }
    }
}
