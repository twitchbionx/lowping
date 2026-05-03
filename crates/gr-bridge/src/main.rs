//! lowping bridge — relay server.
//!
//! Phase 0: empty skeleton. Real work lands in subsequent phases.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "lowping bridge — game traffic relay")]
struct Cli {
    /// Path to bridge config file (TOML).
    #[arg(short, long, env = "LOWPING_BRIDGE_CONFIG", default_value = "bridge.toml")]
    config: std::path::PathBuf,

    /// Verbose logging.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
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

    tracing::info!(config = %cli.config.display(), "lowping bridge starting");
    tracing::warn!("phase 0 skeleton — nothing actually does anything yet");

    // TODO Phase 1: bind UDP socket, accept first frame (must be SYN with
    //               valid CONNECT and authenticated client pubkey), open
    //               socket to the requested destination, splice both ways.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown");
    Ok(())
}
