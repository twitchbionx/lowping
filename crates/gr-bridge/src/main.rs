//! lowping bridge — relay server.
//!
//! Listens on UDP. For each tunnel frame:
//!   - SYN frame: do ECDH with the embedded client pubkey, decrypt payload,
//!     verify the license token, parse the inner CONNECT, open a socket to
//!     the requested destination, register a Session.
//!   - Data frame: look up session by (client_addr, connection_id), decrypt,
//!     forward payload to the destination socket.
//!   - Out-of-band: each session also has a tokio task draining the dest
//!     socket and forwarding payloads back to the client as encrypted frames.

mod config;
mod server;
mod session;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "lowping bridge — game traffic relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the bridge.
    Serve {
        #[arg(short, long, env = "LOWPING_BRIDGE_CONFIG", default_value = "bridge.toml")]
        config: PathBuf,
    },
    /// Generate a fresh X25519 keypair (for first-time setup of `bridge_seckey_hex`).
    GenKey,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,gr_bridge=debug")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { config } => serve(config).await,
        Cmd::GenKey => {
            let (sk, pk) = gr_protocol::handshake::generate_keypair();
            println!("# add to bridge.toml:");
            println!("bridge_x25519_seckey_hex = \"{}\"", hex::encode(sk.to_bytes()));
            println!();
            println!("# clients fetch this pubkey from the backend's bridge directory:");
            println!("# x25519_pubkey_hex = \"{}\"", hex::encode(pk.to_bytes()));
            Ok(())
        }
    }
}

async fn serve(config_path: PathBuf) -> Result<()> {
    let cfg = config::BridgeConfig::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    server::run(cfg).await
}
