//! lowping client — Phase 1: a TCP→tunnel forwarder.
//!
//! No driver yet. This binary listens on a local TCP port. Every connection
//! gets tunneled to a configured bridge, forwarded to a configured destination.
//!
//! When the WFP driver lands (Phase 3) the listener is replaced by a callback
//! from the kernel — same tunnel logic.

mod forwarder;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "lowping client (Phase 1 TCP forwarder)")]
struct Cli {
    /// Path to client config file (TOML).
    #[arg(short, long, env = "LOWPING_CONFIG", default_value = "client.toml")]
    config: PathBuf,
    /// Local TCP listen address (overrides config).
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Verbose logging (-v debug, -vv trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info,gr_client=info",
        1 => "debug,gr_client=debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    forwarder::run(cli.config, cli.listen).await
}
