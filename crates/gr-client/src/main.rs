//! lowping client — Phase 1: a TCP→tunnel forwarder.
//!
//! No driver yet. This binary listens on a local TCP port. Every connection
//! gets tunneled to a configured bridge, forwarded to a configured destination.
//!
//! When the WFP driver lands (Phase 3) the listener is replaced by a callback
//! from the kernel — same tunnel logic.

mod forwarder;
mod router;
mod tui;

#[cfg(windows)]
mod smart;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "lowping client")]
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
    /// Show the live TUI dashboard instead of streaming logs.
    /// Requires smart_routing mode (logs go to file in --log-file).
    #[arg(long)]
    tui: bool,
    /// When --tui is set, write logs here instead of stdout (which is busy).
    #[arg(long, default_value = "lowping.log")]
    log_file: PathBuf,
}

fn init_tracing(verbose: u8, log_file: Option<&PathBuf>) {
    let level = match verbose {
        0 => "info,gr_client=info",
        1 => "debug,gr_client=debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    if let Some(path) = log_file {
        // TUI mode — write logs to a file (stdout is owned by ratatui)
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open log file");
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, if cli.tui { Some(&cli.log_file) } else { None });

    if cli.tui {
        run_with_tui(cli).await
    } else {
        forwarder::run(cli.config, cli.listen).await
    }
}

async fn run_with_tui(cli: Cli) -> Result<()> {
    use anyhow::Context;

    let text = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("reading {}", cli.config.display()))?;
    let cfg: forwarder::Config = toml::from_str(&text)?;

    #[cfg(windows)]
    {
        let smart_cfg = cfg.smart_routing.clone()
            .ok_or_else(|| anyhow::anyhow!("--tui requires [smart_routing] section in config"))?;
        let bridges = smart_cfg.bridges.clone();
        let direct_rtt = smart_cfg.direct_rtt_ms.clone();
        let router = std::sync::Arc::new(crate::router::Router::new(bridges.clone()));

        // Build resolver + capture (mirrors run_smart_mode in forwarder)
        let resolver: std::sync::Arc<dyn gr_capture::RouteResolver> =
            std::sync::Arc::new(crate::smart::SmartResolver::new(router.clone(), direct_rtt));
        let redirect_targets: Vec<SocketAddr> = bridges.iter()
            .map(|b| SocketAddr::new(std::net::IpAddr::V4("127.0.0.1".parse().unwrap()), b.listen_port))
            .collect();
        let bridge_endpoints: Vec<SocketAddr> = bridges.iter().map(|b| b.endpoint).collect();
        let capture = std::sync::Arc::new(gr_capture::WinDivertCapture::with_resolver(
            resolver, redirect_targets, bridge_endpoints,
        ));
        gr_capture::Redirector::start(&*capture)
            .map_err(|e| anyhow::anyhow!("starting capture: {e}\nDid you run as Administrator?"))?;

        // Reuse start_smart to spawn listeners but reuse OUR router so the TUI sees the same state
        // (start_smart creates its own Router; for TUI we want the one we just made)
        for b in &bridges {
            let est = match b.name.as_str() {
                "dallas" => 22.0, "nj" => 35.0, "seattle"|"sea" => 50.0,
                "frankfurt"|"fra" => 110.0, _ => 40.0,
            };
            router.record_client_to_bridge(&b.name, est);
        }
        for (idx, bridge) in bridges.iter().enumerate() {
            let bridge = bridge.clone();
            let cap = capture.clone();
            let listen = SocketAddr::new(std::net::IpAddr::V4("127.0.0.1".parse().unwrap()), bridge.listen_port);
            tokio::spawn(async move {
                if let Err(e) = crate::smart::run_bridge_listener(bridge.clone(), listen, Some(cap)).await {
                    tracing::error!(bridge = %bridge.name, error = ?e, "listener exited");
                }
                let _ = idx;
            });
        }

        // Run the TUI in the main thread (it owns stdout)
        // The router and capture stay alive as long as the TUI runs.
        let router_for_tui = router.clone();
        let capture_for_tui = capture.clone();
        tokio::task::spawn_blocking(move || {
            tui::run(router_for_tui, Some(capture_for_tui))
        }).await??;
    }

    #[cfg(not(windows))]
    {
        anyhow::bail!("--tui mode currently requires Windows (for the WinDivert capture)");
    }
    Ok(())
}
