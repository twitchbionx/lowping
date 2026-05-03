//! UDP server: the bridge's main loop.

use anyhow::{Context, Result};
use chacha20poly1305::Key as AeadKey;
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use gr_protocol::{
    decrypt_frame, decrypt_syn_payload, encrypt_frame, handshake, license::LicenseToken,
    parse_syn_front, ConnectRequest, Flags, Header, MAX_PAYLOAD_LEN, PROTO_VERSION,
    TransportProtocol,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use x25519_dalek::StaticSecret;

use crate::config::BridgeConfig;
use crate::session::{DestSocket, DownstreamPacket, Session, SessionKey};

/// Shared bridge state: the session table + counter.
struct BridgeState {
    sessions: RwLock<HashMap<SessionKey, Arc<tokio::sync::Mutex<Session>>>>,
    config: BridgeConfig,
    bridge_secret: StaticSecret,
    backend_pubkey: VerifyingKey,
    /// Outbound channel: anyone can submit a packet to be encrypted + sent back to a client.
    downstream_tx: mpsc::UnboundedSender<DownstreamPacket>,
}

pub async fn run(cfg: BridgeConfig) -> Result<()> {
    let bridge_secret = cfg.parsed_x25519_secret().context("bridge_x25519_seckey_hex")?;
    let backend_pubkey = cfg.parsed_backend_pubkey().context("backend_ed25519_pubkey_hex")?;

    let socket = Arc::new(
        UdpSocket::bind(cfg.listen)
            .await
            .with_context(|| format!("binding {}", cfg.listen))?,
    );
    tracing::info!(listen = %cfg.listen, "bridge listening");

    let (downstream_tx, downstream_rx) = mpsc::unbounded_channel();

    let state = Arc::new(BridgeState {
        sessions: RwLock::new(HashMap::new()),
        config: cfg,
        bridge_secret,
        backend_pubkey,
        downstream_tx,
    });

    // Spawn the downstream sender — drains the channel and writes encrypted
    // frames back to clients via the listening UDP socket.
    {
        let state = state.clone();
        let socket = socket.clone();
        tokio::spawn(downstream_sender(state, socket, downstream_rx));
    }

    // Spawn the idle reaper — periodically drops sessions with no traffic.
    {
        let state = state.clone();
        tokio::spawn(idle_reaper(state));
    }

    // Main receive loop.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(error = %e, "recv_from failed");
                continue;
            }
        };
        let pkt = buf[..n].to_vec();
        let state = state.clone();
        // Each packet handled in its own task — a slow handshake doesn't block the listener.
        tokio::spawn(async move {
            if let Err(e) = handle_packet(state, peer, pkt).await {
                tracing::debug!(peer = %peer, error = ?e, "drop packet");
            }
        });
    }
}

async fn handle_packet(state: Arc<BridgeState>, peer: SocketAddr, pkt: Vec<u8>) -> Result<()> {
    // Parse the header alone first (no decryption needed for routing).
    let header = Header::decode(&pkt).context("header decode")?;
    if header.version != PROTO_VERSION {
        anyhow::bail!("bad proto version: {}", header.version);
    }
    let key = SessionKey { client_addr: peer, connection_id: header.connection_id };

    if header.flags.contains(Flags::SYN) {
        accept_new_session(state, key, header, pkt).await
    } else {
        forward_data(state, key, pkt).await
    }
}

async fn accept_new_session(
    state: Arc<BridgeState>,
    key: SessionKey,
    header: Header,
    pkt: Vec<u8>,
) -> Result<()> {
    // Refuse if at capacity.
    if state.sessions.read().len() >= state.config.max_sessions {
        anyhow::bail!("session table full");
    }

    let (_h, client_pk_bytes) = parse_syn_front(&pkt)?;
    let client_pk = handshake::pubkey_from_bytes(&client_pk_bytes)?;
    let aead_key = handshake::bridge_derive_session_key(&state.bridge_secret, &client_pk);
    let inner = decrypt_syn_payload(&aead_key, &pkt)?;

    // Inner SYN payload format: [88-byte license token][ConnectRequest...]
    if inner.len() < gr_protocol::license::TOKEN_LEN + 4 {
        anyhow::bail!("SYN payload too short for token + connect");
    }
    let token = LicenseToken::from_bytes(&inner[..gr_protocol::license::TOKEN_LEN])?;
    let now = Utc::now().timestamp();
    token.verify(&state.backend_pubkey, now).context("license verify")?;
    if !state.config.allow_any_scope && (token.payload.scope & 1) == 0 {
        anyhow::bail!("license missing required scope bit 0");
    }

    let connect = ConnectRequest::decode(&inner[gr_protocol::license::TOKEN_LEN..])?;
    tracing::info!(
        client = %key.client_addr, cid = key.connection_id,
        proto = ?connect.protocol, dest = %connect.dest_ip, port = connect.dest_port,
        user_id = token.payload.user_id,
        "accepting session"
    );

    // Open the destination socket.
    let dest = open_dest(&connect).await?;

    let session = Session::new(key, aead_key, dest);
    let session = Arc::new(tokio::sync::Mutex::new(session));
    state.sessions.write().insert(key, session.clone());

    // Spawn the dest→client forwarder.
    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = drain_dest(state2, key, session).await {
            tracing::debug!(?key, error = ?e, "session ended");
        }
    });

    // The SYN frame's payload doesn't carry game data — it only carries the
    // CONNECT. We don't write anything to the dest socket from the SYN.
    let _ = header; // silence unused
    Ok(())
}

async fn forward_data(state: Arc<BridgeState>, key: SessionKey, pkt: Vec<u8>) -> Result<()> {
    let session = match state.sessions.read().get(&key).cloned() {
        Some(s) => s,
        None => anyhow::bail!("no session for {:?}", key),
    };
    let mut sess = session.lock().await;
    let (_h, payload) = decrypt_frame(&sess.aead_key, &pkt)?;
    sess.last_active = std::time::Instant::now();

    match &mut sess.dest {
        DestSocket::Tcp(stream) => {
            stream.write_all(&payload).await.context("tcp write")?;
        }
        DestSocket::Udp(udp) => {
            udp.send(&payload).await.context("udp send")?;
        }
    }
    Ok(())
}

/// Per-session task: read from destination socket, encrypt + send back to client.
async fn drain_dest(
    state: Arc<BridgeState>,
    key: SessionKey,
    session: Arc<tokio::sync::Mutex<Session>>,
) -> Result<()> {
    // Move the dest socket OUT of the Session so we can read in this task
    // without holding the Mutex across await points (which would block
    // other forward_data calls).
    //
    // Phase 1 trick: we keep the socket in the session for writes from
    // forward_data, but create a separate read half for reads. For TCP we
    // can split. For UDP we can't really (single-buffer socket), so we
    // serialize via the session lock with a small buffer per recv.

    loop {
        let mut buf = vec![0u8; MAX_PAYLOAD_LEN];
        let n = {
            let mut sess = session.lock().await;
            match &mut sess.dest {
                DestSocket::Tcp(stream) => {
                    // Brief lock — read available bytes
                    match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await {
                        Ok(Ok(0)) => return Ok(()), // EOF
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => continue, // timeout, loop and check session validity
                    }
                }
                DestSocket::Udp(udp) => {
                    match tokio::time::timeout(Duration::from_secs(60), udp.recv(&mut buf)).await {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => continue,
                    }
                }
            }
        };
        // Hand off to the downstream sender (which holds the UDP listening socket).
        let _ = state.downstream_tx.send(DownstreamPacket {
            session_key: key,
            payload: buf[..n].to_vec(),
        });
    }
}

async fn downstream_sender(
    state: Arc<BridgeState>,
    socket: Arc<UdpSocket>,
    mut rx: mpsc::UnboundedReceiver<DownstreamPacket>,
) {
    while let Some(pkt) = rx.recv().await {
        let session = match state.sessions.read().get(&pkt.session_key).cloned() {
            Some(s) => s,
            None => continue,
        };
        let (header, wire) = {
            let mut sess = session.lock().await;
            sess.tx_sequence = sess.tx_sequence.wrapping_add(1);
            let header = Header {
                version: PROTO_VERSION,
                flags: Flags::empty(),
                connection_id: pkt.session_key.connection_id,
                sequence: sess.tx_sequence,
            };
            let wire = match encrypt_frame(&sess.aead_key, &header, &pkt.payload) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(error = %e, "encrypt failed");
                    continue;
                }
            };
            (header, wire)
        };
        if let Err(e) = socket.send_to(&wire, pkt.session_key.client_addr).await {
            tracing::warn!(error = %e, "downstream send failed");
        }
        let _ = header;
    }
}

async fn idle_reaper(state: Arc<BridgeState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let cutoff = std::time::Instant::now()
            - Duration::from_secs(state.config.idle_timeout_secs);
        let mut to_drop = Vec::new();
        for (key, sess) in state.sessions.read().iter() {
            // Try to acquire without blocking — if locked, it's active anyway
            if let Ok(s) = sess.try_lock() {
                if s.last_active < cutoff {
                    to_drop.push(*key);
                }
            }
        }
        if !to_drop.is_empty() {
            let mut sessions = state.sessions.write();
            for key in &to_drop {
                sessions.remove(key);
            }
            tracing::info!(count = to_drop.len(), "reaped idle sessions");
        }
    }
}

async fn open_dest(connect: &ConnectRequest) -> Result<DestSocket> {
    let addr = SocketAddr::new(connect.dest_ip, connect.dest_port);
    match connect.protocol {
        TransportProtocol::Tcp => {
            let s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
                .await
                .with_context(|| format!("tcp connect timeout to {}", addr))??;
            s.set_nodelay(true).ok();
            Ok(DestSocket::Tcp(s))
        }
        TransportProtocol::Udp => {
            // Bind a fresh ephemeral local port; "connect" the UDP socket so
            // we can use plain send/recv without specifying address each time.
            let local = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let s = UdpSocket::bind(local).await?;
            s.connect(addr).await.with_context(|| format!("udp connect to {}", addr))?;
            Ok(DestSocket::Udp(s))
        }
    }
}
