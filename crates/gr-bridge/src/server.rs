//! UDP server: the bridge's main loop.

use anyhow::{Context, Result};
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
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use x25519_dalek::StaticSecret;

use crate::config::BridgeConfig;
use crate::session::{DestWriter, Session, SessionKey};

enum DestReader {
    Tcp(OwnedReadHalf),
    Udp(Arc<UdpSocket>),
}

pub struct DownstreamPacket {
    pub session_key: SessionKey,
    pub payload: Vec<u8>,
}

struct BridgeState {
    sessions: RwLock<HashMap<SessionKey, Arc<tokio::sync::Mutex<Session>>>>,
    config: BridgeConfig,
    bridge_secret: StaticSecret,
    backend_pubkey: VerifyingKey,
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

    {
        let state = state.clone();
        let socket = socket.clone();
        tokio::spawn(downstream_sender(state, socket, downstream_rx));
    }
    {
        let state = state.clone();
        tokio::spawn(idle_reaper(state));
    }

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
        tokio::spawn(async move {
            if let Err(e) = handle_packet(state, peer, pkt).await {
                tracing::debug!(peer = %peer, error = ?e, "drop packet");
            }
        });
    }
}

async fn handle_packet(state: Arc<BridgeState>, peer: SocketAddr, pkt: Vec<u8>) -> Result<()> {
    let header = Header::decode(&pkt).context("header decode")?;
    if header.version != PROTO_VERSION {
        anyhow::bail!("bad proto version: {}", header.version);
    }
    let key = SessionKey { client_addr: peer, connection_id: header.connection_id };

    if header.flags.contains(Flags::SYN) {
        accept_new_session(state, key, pkt).await
    } else {
        forward_data(state, key, pkt).await
    }
}

async fn accept_new_session(
    state: Arc<BridgeState>,
    key: SessionKey,
    pkt: Vec<u8>,
) -> Result<()> {
    if state.sessions.read().len() >= state.config.max_sessions {
        anyhow::bail!("session table full");
    }

    let (_h, client_pk_bytes) = parse_syn_front(&pkt)?;
    let client_pk = handshake::pubkey_from_bytes(&client_pk_bytes)?;
    let aead_key = handshake::bridge_derive_session_key(&state.bridge_secret, &client_pk);
    let inner = decrypt_syn_payload(&aead_key, &pkt)?;

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

    let (writer, reader) = open_dest(&connect).await?;

    let session = Arc::new(tokio::sync::Mutex::new(Session::new(aead_key, writer)));
    state.sessions.write().insert(key, session);

    // Spawn the dest→client forwarder. Uses the OWNED read half — no lock contention.
    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = drain_dest(state2, key, reader).await {
            tracing::debug!(?key, error = ?e, "session ended");
        }
    });

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
    let len = payload.len();

    match &mut sess.dest_writer {
        DestWriter::Tcp(stream) => {
            stream.write_all(&payload).await.context("tcp write")?;
        }
        DestWriter::Udp(udp) => {
            udp.send(&payload).await.context("udp send")?;
        }
    }
    tracing::trace!(?key, bytes = len, "forwarded to dest");
    Ok(())
}

/// Per-session task: read from destination, queue back to the client.
/// Does NOT touch the session mutex — that's why we own a separate read half.
async fn drain_dest(
    state: Arc<BridgeState>,
    key: SessionKey,
    mut reader: DestReader,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_PAYLOAD_LEN];
    loop {
        let n = match &mut reader {
            DestReader::Tcp(r) => match r.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) => return Err(e.into()),
            },
            DestReader::Udp(udp) => match udp.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => return Err(e.into()),
            },
        };
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
        let wire = {
            let mut sess = session.lock().await;
            sess.tx_sequence = sess.tx_sequence.wrapping_add(1);
            let header = Header {
                version: PROTO_VERSION,
                flags: Flags::empty(),
                connection_id: pkt.session_key.connection_id,
                sequence: sess.tx_sequence,
            };
            match encrypt_frame(&sess.aead_key, &header, &pkt.payload) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(error = %e, "encrypt failed");
                    continue;
                }
            }
        };
        if let Err(e) = socket.send_to(&wire, pkt.session_key.client_addr).await {
            tracing::warn!(error = %e, "downstream send failed");
        }
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

async fn open_dest(connect: &ConnectRequest) -> Result<(DestWriter, DestReader)> {
    let addr = SocketAddr::new(connect.dest_ip, connect.dest_port);
    match connect.protocol {
        TransportProtocol::Tcp => {
            let s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
                .await
                .with_context(|| format!("tcp connect timeout to {}", addr))??;
            s.set_nodelay(true).ok();
            let (r, w) = s.into_split();
            Ok((DestWriter::Tcp(w), DestReader::Tcp(r)))
        }
        TransportProtocol::Udp => {
            let local = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let s = Arc::new(UdpSocket::bind(local).await?);
            s.connect(addr).await.with_context(|| format!("udp connect to {}", addr))?;
            Ok((DestWriter::Udp(s.clone()), DestReader::Udp(s)))
        }
    }
}
