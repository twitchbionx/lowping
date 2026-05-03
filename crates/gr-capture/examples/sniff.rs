//! Smoke test: open WinDivert and log packets matching a simple filter.
//!
//! Run as Administrator:
//!   cargo run -p gr-capture --example sniff --release -- --filter "udp"
//!   # or to test redirect logic:
//!   cargo run -p gr-capture --example sniff --release -- \
//!       --rule "udp,1.1.1.1:53,127.0.0.1:9999"
//!
//! Without --rule it just sniffs (passthru). With --rule it sets up DNAT.
//!
//! Note: WinDivert requires Administrator privileges. The first time it runs
//! it will install the .sys driver (signed by Sectigo EV, but your AV may
//! still beep about it).

use clap::Parser;
use gr_capture::{
    windivert_backend::WinDivertCapture, Protocol, RedirectRule, Redirector,
};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// Add a redirect rule of the form "udp,DST_IP:DST_PORT_LO[-DST_PORT_HI],LOCAL_IP:LOCAL_PORT"
    /// Example: "udp,1.1.1.1:53,127.0.0.1:9999"
    /// Repeatable.
    #[arg(long, value_name = "SPEC")]
    rule: Vec<String>,

    /// Run for this many seconds, then exit. Default 30.
    #[arg(short, long, default_value = "30")]
    duration: u64,
}

fn parse_rule(s: &str) -> Result<RedirectRule, String> {
    // Format: proto,dst_ip:dst_port[-port_hi],local_ip:local_port
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(format!("expected 3 comma-separated parts, got {}", parts.len()));
    }
    let protocol = match parts[0].to_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => return Err(format!("unknown protocol: {other}")),
    };

    // dst part: ip:port or ip:port_lo-port_hi
    let dst_split: Vec<&str> = parts[1].rsplitn(2, ':').collect();
    if dst_split.len() != 2 {
        return Err("dst spec missing colon".into());
    }
    let dst_ip = dst_split[1].parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
    let port_part = dst_split[0];
    let (lo, hi) = if let Some(idx) = port_part.find('-') {
        let l: u16 = port_part[..idx].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        let h: u16 = port_part[idx + 1..].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        (l, h)
    } else {
        let p: u16 = port_part.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        (p, p)
    };

    let local: SocketAddr = parts[2].parse().map_err(|e: std::net::AddrParseError| e.to_string())?;

    Ok(RedirectRule {
        protocol,
        dst_ip,
        dst_port_lo: lo,
        dst_port_hi: hi,
        redirect_to_ip: local.ip(),
        redirect_to_port: local.port(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,gr_capture=trace")),
        )
        .init();

    let rules: Vec<RedirectRule> = cli
        .rule
        .iter()
        .map(|s| parse_rule(s))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("rule parse: {e}"))?;

    if rules.is_empty() {
        eprintln!("must supply at least one --rule (try `--rule \"udp,1.1.1.1:53,127.0.0.1:9999\"`)");
        std::process::exit(2);
    }

    println!("rules:");
    for r in &rules {
        println!("  {:?}", r);
    }

    let cap = WinDivertCapture::new(rules);
    cap.start()?;
    println!("capture running for {}s. Generate matching traffic to see redirects.", cli.duration);

    let mut elapsed = 0;
    while elapsed < cli.duration {
        std::thread::sleep(Duration::from_secs(5));
        elapsed += 5;
        let s = cap.stats();
        println!(
            "[{}s] outbound={} inbound={} dropped={} flows={}",
            elapsed,
            s.outbound_redirected,
            s.inbound_rewritten,
            s.dropped_unparseable,
            s.active_flows,
        );
    }

    cap.stop()?;
    println!("done");
    Ok(())
}
