//! Phase 1 tunnel forwarder.
//!
//! Reads a config file describing one or more "rules":
//!   listen = "127.0.0.1:9000"
//!   bridge = "203.0.113.5:51820"
//!   bridge_x25519_pubkey_hex = "..."
//!   license_token = "<base64 token>"
//!   dest_ip = "1.2.3.4"
//!   dest_port = 80
//!   protocol = "tcp"  # or "udp"
//!
//! For each accepted local connection, opens a UDP tunnel to the bridge,
//! sends a SYN frame with the embedded license + CONNECT, and pipes bytes
//! in both directions until the connection closes.

use anyhow::{Context, Result};
use chacha20poly1305::Key as AeadKey;
use gr_protocol::{
    encrypt_frame, encrypt_syn_frame, decrypt_frame, handshake,
    license::LicenseToken, ConnectRequest, Flags, Header, MAX_PAYLOAD_LEN,
    PROTO_VERSION, TransportProtocol,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Debug, Deserialize, Clone)]
struct Rule {
    /// Local address to listen on.
    listen: SocketAddr,
    /// Bridge endpoint (host:port).
    bridge: SocketAddr,
    /// Bridge's X25519 public key (32 bytes hex).
    bridge_x25519_pubkey_hex: String,
    /// Our license token (base64-url, no padding).
    license_token: String,
    /// Destination IP (where the bridge forwards to).
    dest_ip: IpAddr,
    /// Destination port.
    dest_port: u16,
    /// "tcp" or "udp" — protocol for the destination side.
    #[serde(default = "default_proto")]
    protocol: String,
}

fn default_proto() -> String { "tcp".into() }

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
        let h = tokio::spawn(run_rule(rule));
        handles.push(h);
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_rule(rule: Rule) -> Result<()> {
    let listener = TcpListener::bind(rule.listen).await
        .with_context(|| format!("binding {}", rule.listen))?;
    tracing::info!(
        listen = %rule.listen, bridge = %rule.bridge,
        dest = %format!("{}:{}", rule.dest_ip, rule.dest_port),
        "rule active"
    );
    let rule = Arc::new(rule);
    loop {
        let (stream, peer) = listener.accept().await?;
        let rule = rule.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local_connection(rule, stream, peer).await {
                tracing::warn!(peer = %peer, error = ?e, "connection ended");
            }
        });
    }
}

async fn handle_local_connection(
    rule: Arc<Rule>,
    local: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    tracing::info!(local = %peer, dest = %format!("{}:{}", rule.dest_ip, rule.dest_port), "tunnel up");

    // Generate ephemeral X25519 keypair for this tunnel.
    let (client_sk, client_pk) = handshake::generate_keypair();

    // Parse bridge pubkey + license token from config.
    let bridge_pk_bytes = hex::decode(&rule.bridge_x25519_pubkey_hex)
        .context("bridge_x25519_pubkey_hex")?;
    let bridge_pk = handshake::pubkey_from_bytes(&bridge_pk_bytes)?;
    let aead_key = handshake::client_derive_session_key(&client_sk, &bridge_pk);
    let token = LicenseToken::from_string_b64(&rule.license_token)
        .context("license_token decode")?;

    // Random connection_id per tunnel.
    let connection_id = OsRng.next_u32();

    // Open the UDP socket to the bridge.
    let bind_addr = if rule.bridge.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
    udp.connect(rule.bridge).await
        .with_context(|| format!("udp connect to bridge {}", rule.bridge))?;

    // Build and send the SYN.
    let proto = match rule.protocol.as_str() {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        other => anyhow::bail!("unknown protocol: {}", other),
    };
    let connect = ConnectRequest {
        protocol: proto,
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

    // Now pipe bytes in both directions.
    let aead_key = Arc::new(aead_key);
    let udp_for_recv = udp.clone();
    let aead_for_recv = aead_key.clone();

    // Split local TCP into owned halves so each can move into its own task.
    let (mut local_r, mut local_w) = local.into_split();

    // Sequence counter for tx.
    let mut tx_sequence: u64 = 0;
    let mut buf = vec![0u8; MAX_PAYLOAD_LEN];

    // Spawn a task to read from UDP and write to local.
    let recv_task = tokio::spawn(async move {
        let mut rbuf = vec![0u8; 64 * 1024];
        loop {
            let n = match tokio::time::timeout(Duration::from_secs(60), udp_for_recv.recv(&mut rbuf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err::<(), anyhow::Error>(e.into()),
                Err(_) => continue, // timeout, keep waiting
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

    // Forward local→bridge in this task.
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), local_r.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
            Err(_) => continue,
        };
        tx_sequence = tx_sequence.wrapping_add(1);
        let header = Header {
            version: PROTO_VERSION,
            flags: Flags::empty(),
            connection_id,
            sequence: tx_sequence,
        };
        let wire = encrypt_frame(&aead_key, &header, &buf[..n])?;
        udp.send(&wire).await?;
    }

    recv_task.abort();
    let _ = aead_key; // keep alive
    Ok(())
}
