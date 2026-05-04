//! Smart-routing mode for grclient.
//!
//! Activates when `client.toml` has a `[[bridges]]` array (vs the legacy
//! per-`[[rules]]` static dest config). Architecture:
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────────┐
//!   │ WinDivertCapture (Network layer, broad UDP filter)               │
//!   │   resolver: Box<dyn RouteResolver = SmartResolver(Router)>       │
//!   │     for each outbound packet:                                    │
//!   │       Router::pick(dst, direct_rtt) → Direct or ViaBridge(idx)   │
//!   │       Direct      → passthrough (no NAT entry)                   │
//!   │       ViaBridge   → DNAT to 127.0.0.1:bridges[idx].listen_port,  │
//!   │                     save (game_src_port → orig_dst) flow entry   │
//!   └──────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//!   ┌──────────────────────────────────────────────────────────────────┐
//!   │ One UDP listener per bridge, on its listen_port                  │
//!   │   for each incoming UDP datagram from 127.0.0.1:game_src_port:   │
//!   │     orig_dst = capture.flow_origin(game_src_port)                │
//!   │     session = sessions.entry(game_src_port).or_insert(           │
//!   │       open_tunnel(bridge, orig_dst))                             │
//!   │     session.forward(payload)                                     │
//!   └──────────────────────────────────────────────────────────────────┘
//! ```

use anyhow::{Context, Result};
use chacha20poly1305::Key as AeadKey;
use gr_capture::{Protocol, RouteAction, RouteResolver, WinDivertCapture, Redirector};
use gr_protocol::{
    decrypt_frame, encrypt_frame, encrypt_syn_frame, handshake,
    license::LicenseToken, ConnectRequest, Flags, Header, MAX_PAYLOAD_LEN,
    PROTO_VERSION, TransportProtocol,
};
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::router::{BridgeEntry, Route, Router};

#[derive(Debug, Deserialize, Clone)]
pub struct SmartRoutingConfig {
    /// Bridges to consider. Each gets its own UDP listener on `listen_port`.
    pub bridges: Vec<BridgeEntry>,
    /// Direct-RTT estimate per AWS region (ms). Without these the router
    /// always picks a bridge (since direct_rtt = ∞ by default).
    /// Future: replaced by live ICMP probing.
    #[serde(default)]
    pub direct_rtt_ms: HashMap<String, f64>,
    /// Hysteresis margin in ms — only choose a bridge if it beats direct
    /// by this margin. Default 2.0.
    #[serde(default = "default_margin")]
    pub margin_ms: f64,
}

fn default_margin() -> f64 { 2.0 }

/// RouteResolver impl that wraps the Router and looks up direct RTT estimates
/// from the config's region table.
pub struct SmartResolver {
    router: Arc<Router>,
    direct_rtt_ms: HashMap<String, f64>,
    aws: gr_common::aws_regions::AwsLookup,
}

impl SmartResolver {
    pub fn new(router: Arc<Router>, direct_rtt_ms: HashMap<String, f64>) -> Self {
        Self {
            router,
            direct_rtt_ms,
            aws: gr_common::aws_regions::AwsLookup::load_bundled(),
        }
    }
}

impl RouteResolver for SmartResolver {
    fn resolve(&self, dst: SocketAddr, _protocol: Protocol) -> RouteAction {
        // Look up region → direct RTT estimate
        let direct_rtt = self
            .aws
            .region_for(dst.ip())
            .and_then(|r| self.direct_rtt_ms.get(r).copied())
            .unwrap_or(f64::INFINITY); // unknown direct path → assume bad

        let route = self.router.pick(dst, direct_rtt);
        match route {
            Route::Direct => RouteAction::Passthrough,
            Route::ViaBridge(idx) => {
                let b = &self.router.bridges()[idx];
                RouteAction::RewriteTo(SocketAddr::new("127.0.0.1".parse().unwrap(), b.listen_port))
            }
        }
    }
}

// =============================================================================
// Per-bridge dynamic UDP forwarder
// =============================================================================

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

type SessionMap = Arc<RwLock<HashMap<u16, Arc<UdpSession>>>>;

pub async fn run_smart(
    cfg: SmartRoutingConfig,
    capture: Option<Arc<WinDivertCapture>>,
) -> Result<()> {
    let router = Arc::new(Router::new(cfg.bridges.clone()));

    // For now: hardcoded baseline (ICMP probing comes next iteration).
    // We assume client→bridge ≈ direct ping to bridge endpoint.
    // TODO: replace with live ICMP probe at startup + every N seconds.
    for b in &cfg.bridges {
        // Cheap heuristic: just use a fixed estimate per bridge name. Operator
        // can override via region_rtt_ms in config.
        // Better: ICMP ping.
        router.record_client_to_bridge(&b.name, 30.0);
        tracing::info!(bridge = %b.name, "added to router with placeholder client_rtt = 30.0ms");
    }

    // Spawn one UDP listener per bridge.
    let mut handles = Vec::new();
    for (idx, bridge) in cfg.bridges.iter().enumerate() {
        let bridge = bridge.clone();
        let capture = capture.clone();
        let listen = SocketAddr::new("127.0.0.1".parse().unwrap(), bridge.listen_port);
        let h = tokio::spawn(async move {
            if let Err(e) = run_bridge_listener(bridge.clone(), listen, capture).await {
                tracing::error!(bridge = %bridge.name, error = ?e, "listener exited");
            }
            let _ = idx;
        });
        handles.push(h);
    }

    // Block on all listeners
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_bridge_listener(
    bridge: BridgeEntry,
    listen: SocketAddr,
    capture: Option<Arc<WinDivertCapture>>,
) -> Result<()> {
    let listener = Arc::new(UdpSocket::bind(listen).await
        .with_context(|| format!("binding udp {}", listen))?);
    tracing::info!(
        bridge = %bridge.name, listen = %listen, endpoint = %bridge.endpoint,
        "smart bridge listener active"
    );
    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, src) = match listener.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(error = %e, "udp recv_from failed");
                continue;
            }
        };
        let src_port = src.port();
        let payload = buf[..n].to_vec();

        let existing = sessions.read().get(&src_port).cloned();
        let session = match existing {
            Some(s) => s,
            None => {
                // Look up where the game wanted to send this datagram
                let orig_dest = match capture.as_ref().and_then(|c| c.flow_origin(src_port)) {
                    Some(d) => d,
                    None => {
                        tracing::warn!(src_port, "no flow_origin — dropping packet");
                        continue;
                    }
                };
                tracing::info!(bridge = %bridge.name, src = %src, dest = %orig_dest,
                    "new dynamic udp tunnel");
                let tunnel = match open_tunnel(&bridge, orig_dest).await {
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
                sessions.write().insert(src_port, session.clone());

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
                            Err(_) => continue,
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

struct OpenedTunnel {
    udp_to_bridge: Arc<UdpSocket>,
    aead_key: Arc<AeadKey>,
    connection_id: u32,
}

async fn open_tunnel(bridge: &BridgeEntry, dest: SocketAddr) -> Result<OpenedTunnel> {
    let (client_sk, client_pk) = handshake::generate_keypair();
    let bridge_pk_bytes = hex::decode(&bridge.bridge_x25519_pubkey_hex)
        .context("bridge_x25519_pubkey_hex")?;
    let bridge_pk = handshake::pubkey_from_bytes(&bridge_pk_bytes)?;
    let aead_key = handshake::client_derive_session_key(&client_sk, &bridge_pk);
    let token = LicenseToken::from_string_b64(&bridge.license_token)
        .context("license_token decode")?;

    let connection_id = OsRng.next_u32();
    let bind_addr = if bridge.endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
    udp.connect(bridge.endpoint).await
        .with_context(|| format!("udp connect to bridge {}", bridge.endpoint))?;

    let connect = ConnectRequest {
        protocol: TransportProtocol::Udp,
        dest_ip: dest.ip(),
        dest_port: dest.port(),
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
