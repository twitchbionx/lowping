//! Phase 1 tunnel forwarder.
//!
//! Reads a config file describing one or more "rules":
//!   listen = "127.0.0.1:9000"
//!   bridge = "203.0.113.5:51820"
//!   bridge_x25519_pubkey_hex = "..."
//!   license_token = "<base64 token>"
//!   dest_ip = "1.2.3.4"
//!   dest_port = 80
//!   protocol = "tcp"  # or "udp" — applies to BOTH local listen and dest
//!
//! For TCP rules: each accepted local connection becomes one tunnel.
//! For UDP rules: each unique local source (src_ip, src_port) becomes one
//! tunnel; idle UDP sessions are reaped after `udp_idle_secs` (default 90s).

use anyhow::{Context, Result};
use chacha20poly1305::Key as AeadKey;
use gr_protocol::{
    encrypt_frame, encrypt_syn_frame, decrypt_frame, handshake,
    license::LicenseToken, ConnectRequest, Flags, Header, MAX_PAYLOAD_LEN,
    PROTO_VERSION, TransportProtocol,
};
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Debug, Deserialize, Clone)]
struct Rule {
    listen: SocketAddr,
    bridge: SocketAddr,
    bridge_x25519_pubkey_hex: String,
    license_token: String,
    dest_ip: IpAddr,
    dest_port: u16,
    /// "tcp" or "udp" — applies to local listen AND dest forwarding.
    #[serde(default = "default_proto")]
    protocol: String,
    /// For UDP rules: drop a session after this many seconds idle. Default 90.
    #[serde(default = "default_udp_idle")]
    udp_idle_secs: u64,
}

fn default_proto() -> String { "tcp".into() }
fn default_udp_idle() -> u64 { 90 }

#[derive(Debug, Deserialize)]
struct Config {
    rules: Vec<Rule>,
}

pub async fn run(config_path: std::path::PathBuf, listen_override: Option<SocketAddr>) -> Result<()> {
    let text = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let mut cfg: Config = toml::from_str(&text)?;

    if let Some(addr) = listen_override {
        if cfg.rules.is_empty() {
            anyhow::bail!("--listen given but no rules in config");
        }
        cfg.rules[0].listen = addr;
    }

    let mut handles = Vec::new();
    for rule in cfg.rules {
        let h = tokio::spawn(run_rule(Arc::new(rule)));
        handles.push(h);
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_rule(rule: Arc<Rule>) -> Result<()> {
    match rule.protocol.as_str() {
        "tcp" => run_tcp_rule(rule).await,
        "udp" => run_udp_rule(rule).await,
        other => anyhow::bail!("unknown protocol: {}", other),
    }
}

// ============================================================================
// Shared SYN handshake — produces an opened tunnel ready for data frames.
// ============================================================================

struct OpenedTunnel {
    /// UDP socket connected to the bridge (use send/recv).
    udp_to_bridge: Arc<UdpSocket>,
    aead_key: Arc<AeadKey>,
    connection_id: u32,
}

async fn open_tunnel(rule: &Rule, transport: TransportProtocol) -> Result<OpenedTunnel> {
    let (client_sk, client_pk) = handshake::generate_keypair();
    let bridge_pk_bytes = hex::decode(&rule.bridge_x25519_pubkey_hex)
        .context("bridge_x25519_pubkey_hex")?;
    let bridge_pk = handshake::pubkey_from_bytes(&bridge_pk_bytes)?;
    let aead_key = handshake::client_derive_session_key(&client_sk, &bridge_pk);
    let token = LicenseToken::from_string_b64(&rule.license_token)
        .context("license_token decode")?;

    let connection_id = OsRng.next_u32();
    let bind_addr = if rule.bridge.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
    udp.connect(rule.bridge).await
        .with_context(|| format!("udp connect to bridge {}", rule.bridge))?;

    let connect = ConnectRequest {
        protocol: transport,
        dest_ip: rule.dest_ip,
        dest_port: rule.dest_port,
    };
    let mut inner = Vec::with_capacity(gr_protocol::license::TOKEN_LEN + 32);
    inner.extend_from_slice(&token.to_bytes());
    inner.extend_from_slice(&connect.encode());

    let header = Header {
        version: PROTO_VERSION,
        flags: Flags::SYN,
        connection_id,
        sequence: 0,
    };
    let client_pk_bytes = client_pk.to_bytes();
    let syn_wire = encrypt_syn_frame(&aead_key, &header, &client_pk_bytes, &inner)?;
    udp.send(&syn_wire).await.context("syn send")?;

    Ok(OpenedTunnel {
        udp_to_bridge: udp,
        aead_key: Arc::new(aead_key),
        connection_id,
    })
}

// ============================================================================
// TCP path — one local connection = one tunnel.
// ============================================================================

async fn run_tcp_rule(rule: Arc<Rule>) -> Result<()> {
    let listener = TcpListener::bind(rule.listen).await
        .with_context(|| format!("binding tcp {}", rule.listen))?;
    tracing::info!(
        listen = %rule.listen, bridge = %rule.bridge,
        dest = %format!("{}:{}", rule.dest_ip, rule.dest_port),
        proto = "tcp",
        "rule active"
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        let rule = rule.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_local(rule, stream, peer).await {
                tracing::warn!(peer = %peer, error = ?e, "tcp connection ended");
            }
        });
    }
}

async fn handle_tcp_local(rule: Arc<Rule>, local: TcpStream, peer: SocketAddr) -> Result<()> {
    tracing::info!(local = %peer, dest = %format!("{}:{}", rule.dest_ip, rule.dest_port), "tcp tunnel up");
    let tunnel = open_tunnel(&rule, TransportProtocol::Tcp).await?;
    let (mut local_r, mut local_w) = local.into_split();

    let aead_for_recv = tunnel.aead_key.clone();
    let udp_for_recv = tunnel.udp_to_bridge.clone();
    let recv_task = tokio::spawn(async move {
        let mut rbuf = vec![0u8; 64 * 1024];
        loop {
            let n = match tokio::time::timeout(Duration::from_secs(60), udp_for_recv.recv(&mut rbuf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => continue,
            };
            let (_h, payload) = match decrypt_frame(&aead_for_recv, &rbuf[..n]) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "drop bridge frame");
                    continue;
                }
            };
            if local_w.write_all(&payload).await.is_err() {
                return Ok(());
            }
        }
    });

    let mut tx_sequence: u64 = 0;
    let mut buf = vec![0u8; MAX_PAYLOAD_LEN];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), local_r.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
            Err(_) => continue,
        };
        tx_sequence = tx_sequence.wrapping_add(1);
        let header = Header {
            version: PROTO_VERSION, flags: Flags::empty(),
            connection_id: tunnel.connection_id, sequence: tx_sequence,
        };
        let wire = encrypt_frame(&tunnel.aead_key, &header, &buf[..n])?;
        tunnel.udp_to_bridge.send(&wire).await?;
    }
    recv_task.abort();
    Ok(())
}

// ============================================================================
// UDP path — one (src_ip, src_port) = one tunnel.
// ============================================================================

struct UdpSession {
    udp_to_bridge: Arc<UdpSocket>,
    aead_key: Arc<AeadKey>,
    connection_id: u32,
    tx_sequence: AtomicU64,
    last_active: parking_lot::Mutex<Instant>,
}

impl UdpSession {
    fn touch(&self) {
        *self.last_active.lock() = Instant::now();
    }
}

type SessionMap = Arc<RwLock<HashMap<SocketAddr, Arc<UdpSession>>>>;

async fn run_udp_rule(rule: Arc<Rule>) -> Result<()> {
    let listener = Arc::new(
        UdpSocket::bind(rule.listen).await
            .with_context(|| format!("binding udp {}", rule.listen))?
    );
    tracing::info!(
        listen = %rule.listen, bridge = %rule.bridge,
        dest = %format!("{}:{}", rule.dest_ip, rule.dest_port),
        proto = "udp",
        "rule active"
    );
    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));

    // Idle reaper.
    {
        let sessions = sessions.clone();
        let idle = Duration::from_secs(rule.udp_idle_secs);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let cutoff = Instant::now() - idle;
                let mut to_drop = Vec::new();
                {
                    let r = sessions.read();
                    for (k, s) in r.iter() {
                        if *s.last_active.lock() < cutoff {
                            to_drop.push(*k);
                        }
                    }
                }
                if !to_drop.is_empty() {
                    let mut w = sessions.write();
                    for k in &to_drop { w.remove(k); }
                    tracing::debug!(count = to_drop.len(), "reaped idle udp sessions");
                }
            }
        });
    }

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, src) = match listener.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(error = %e, "udp listener recv_from failed");
                continue;
            }
        };
        let payload = buf[..n].to_vec();

        // Look up or create session for this source.
        // Release the read guard BEFORE any .await — parking_lot guards aren't Send.
        let existing = sessions.read().get(&src).cloned();
        let session = match existing {
            Some(s) => s,
            None => {
                tracing::info!(src = %src, dest = %format!("{}:{}", rule.dest_ip, rule.dest_port), "new udp tunnel");
                let tunnel = match open_tunnel(&rule, TransportProtocol::Udp).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(error = ?e, "open_tunnel failed");
                        continue;
                    }
                };
                let session = Arc::new(UdpSession {
                    udp_to_bridge: tunnel.udp_to_bridge.clone(),
                    aead_key: tunnel.aead_key.clone(),
                    connection_id: tunnel.connection_id,
                    tx_sequence: AtomicU64::new(0),
                    last_active: parking_lot::Mutex::new(Instant::now()),
                });
                sessions.write().insert(src, session.clone());

                // Spawn the bridge → local responder task.
                let listener = listener.clone();
                let udp_for_recv = tunnel.udp_to_bridge.clone();
                let aead_for_recv = tunnel.aead_key.clone();
                let session_for_recv = session.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 64 * 1024];
                    loop {
                        let n = match tokio::time::timeout(
                            Duration::from_secs(120),
                            udp_for_recv.recv(&mut rbuf),
                        ).await {
                            Ok(Ok(n)) => n,
                            Ok(Err(_)) => return,
                            Err(_) => continue, // listener-side reaper handles real cleanup
                        };
                        let (_h, payload) = match decrypt_frame(&aead_for_recv, &rbuf[..n]) {
                            Ok(x) => x,
                            Err(e) => {
                                tracing::warn!(error = %e, "drop bridge frame");
                                continue;
                            }
                        };
                        if let Err(e) = listener.send_to(&payload, src).await {
                            tracing::warn!(error = %e, "send back to local failed");
                            return;
                        }
                        session_for_recv.touch();
                    }
                });
                session
            }
        };

        // Forward the inbound datagram.
        session.touch();
        let seq = session.tx_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::empty(),
            connection_id: session.connection_id,
            sequence: seq,
        };
        match encrypt_frame(&session.aead_key, &header, &payload) {
            Ok(wire) => {
                if let Err(e) = session.udp_to_bridge.send(&wire).await {
                    tracing::warn!(error = %e, "udp send to bridge failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "udp encrypt failed"),
        }
    }
}
