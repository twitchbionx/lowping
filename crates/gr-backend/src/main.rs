//! lowping backend — bridge directory + license issuance.

mod directory;
mod routes;
mod state;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "lowping backend service")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the HTTP server.
    Serve {
        #[arg(short, long, env = "LOWPING_BACKEND_CONFIG", default_value = "backend.toml")]
        config: PathBuf,
    },
    /// Generate a fresh Ed25519 keypair (for first-time setup of `backend_seckey_hex`).
    GenKey,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tower_http=debug")),
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
            use ed25519_dalek::SigningKey;
            use rand_core::OsRng;
            let sk = SigningKey::generate(&mut OsRng);
            println!("# add to backend.toml:");
            println!("backend_seckey_hex = \"{}\"", hex::encode(sk.to_bytes()));
            println!();
            println!("# clients embed this pubkey to verify directories + tokens:");
            println!("# pubkey_hex = \"{}\"", hex::encode(sk.verifying_key().as_bytes()));
            Ok(())
        }
    }
}

async fn serve(config_path: PathBuf) -> Result<()> {
    let config = state::BackendConfig::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let listen = config.listen;
    let state = state::AppState::new(config, config_path)?;
    let app = routes::router(state);

    tracing::info!(%listen, "lowping backend listening");

    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
