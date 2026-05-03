//! lowping — command-line frontend.
//!
//! Lets you manage bridges, view status, and configure rules without the UI.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "lowping CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Add a bridge to your config.
    AddBridge {
        /// Bridge name shown in the UI.
        name: String,
        /// host:port
        endpoint: String,
        /// Bridge's Ed25519 public key (hex).
        pubkey: String,
    },
    /// List configured bridges.
    ListBridges,
    /// Probe latency to all configured bridges.
    Probe,
    /// Show current connection status.
    Status,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::AddBridge { name, endpoint, pubkey } => {
            println!("TODO: add bridge {name} at {endpoint} (pk={pubkey})");
        }
        Cmd::ListBridges => println!("TODO: list bridges"),
        Cmd::Probe => println!("TODO: probe bridges"),
        Cmd::Status => println!("TODO: status"),
    }
    Ok(())
}
