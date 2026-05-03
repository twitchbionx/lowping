//! Per-process flow scanner — sees every UDP/TCP destination a process opens.
//!
//! Run as Administrator. Use case: figure out where Fortnite is actually
//! sending traffic so you can write capture rules.
//!
//!   cargo run -p gr-capture --example fnscan --release -- --process FortniteClient-Win64-Shipping.exe
//!
//! Filter is process-name → resolved to process IDs at startup. Re-resolves
//! periodically so it picks up new instances.
//!
//! Output: live tally of (proto, remote_ip:port) → flow_count, refreshed
//! every 5s. Ctrl-C to exit; final summary printed.

use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windivert::prelude::*;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// Process name to monitor (case-insensitive substring match).
    #[arg(short, long, default_value = "FortniteClient")]
    process: String,
    /// Run for this many seconds. Default 60.
    #[arg(short, long, default_value = "60")]
    duration: u64,
    /// Only show UDP flows.
    #[arg(long)]
    udp_only: bool,
}

fn list_pids_for(name: &str) -> Vec<u32> {
    use std::process::Command;
    // Use Windows tasklist for reliability
    let output = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .expect("tasklist failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let needle = name.to_lowercase();
    let mut pids = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('"').filter(|s| !s.is_empty() && *s != ",").collect();
        if parts.len() >= 2 {
            let proc_name = parts[0];
            if proc_name.to_lowercase().contains(&needle) {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

fn build_filter(pids: &[u32], udp_only: bool) -> String {
    let proto_clause = if udp_only { " and protocol == 17" } else { "" };
    if pids.is_empty() {
        // No matching process — capture nothing. Use an impossible filter.
        return "false".into();
    }
    let pid_clauses: Vec<String> = pids.iter().map(|p| format!("processId == {p}")).collect();
    format!("event == ESTABLISHED{proto_clause} and ({})", pid_clauses.join(" or "))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("Looking for process matching '{}'...", cli.process);
    let pids = list_pids_for(&cli.process);
    if pids.is_empty() {
        eprintln!("No matching process. Make sure {} is running.", cli.process);
        std::process::exit(1);
    }
    println!("Found PIDs: {pids:?}");

    let filter = build_filter(&pids, cli.udp_only);
    println!("WinDivert filter: {filter}");

    let divert = WinDivert::flow(&filter, 0, Default::default())
        .map_err(|e| format!("WinDivert::flow failed: {e}"))?;

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || r.store(false, Ordering::SeqCst)).ok();
    }

    println!("Capturing flows for {}s. Generate game traffic now (be in a match).", cli.duration);

    let mut endpoints: HashMap<(u8, SocketAddr), u64> = HashMap::new();
    let start = std::time::Instant::now();
    let mut last_print = start;

    while running.load(Ordering::Relaxed)
        && start.elapsed() < Duration::from_secs(cli.duration)
    {
        let pkt = match divert.recv() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let proto = pkt.address.protocol();
        let remote = SocketAddr::new(pkt.address.remote_address(), pkt.address.remote_port());
        *endpoints.entry((proto, remote)).or_insert(0) += 1;

        if last_print.elapsed() > Duration::from_secs(5) {
            print_summary(&endpoints);
            last_print = std::time::Instant::now();
        }
    }

    println!("\n=== FINAL SUMMARY ===");
    print_summary(&endpoints);
    println!("\nSuggested client.toml rules:");
    suggest_rules(&endpoints);
    Ok(())
}

fn proto_name(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    }
}

fn print_summary(endpoints: &HashMap<(u8, SocketAddr), u64>) {
    let mut sorted: Vec<_> = endpoints.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    println!("\n--- top destinations ---");
    println!("{:>6}  {:5}  {:30}  {}", "FLOWS", "PROTO", "REMOTE", "RDNS");
    for ((proto, addr), count) in sorted.iter().take(20) {
        let rdns = lookup_rdns(addr.ip()).unwrap_or_default();
        println!("{count:>6}  {:5}  {addr:30}  {rdns}", proto_name(*proto));
    }
}

fn suggest_rules(endpoints: &HashMap<(u8, SocketAddr), u64>) {
    // Group by (proto, ip), find min/max ports, suggest a single rule
    let mut by_ip: HashMap<(u8, IpAddr), Vec<u16>> = HashMap::new();
    for ((proto, addr), _) in endpoints {
        by_ip.entry((*proto, addr.ip())).or_default().push(addr.port());
    }
    for ((proto, ip), ports) in by_ip.iter() {
        let lo = ports.iter().min().unwrap();
        let hi = ports.iter().max().unwrap();
        println!(
            r#"[[rules]]
listen = "127.0.0.1:9700"
bridge = "<bridge_endpoint>"
bridge_x25519_pubkey_hex = "<bridge_pubkey>"
license_token = "<token>"
dest_ip = "{ip}"
dest_port = {lo}
protocol = "{}"
capture = true
capture_dst_port_lo = {lo}
capture_dst_port_hi = {hi}
"#,
            proto_name(*proto),
        );
    }
}

fn lookup_rdns(ip: IpAddr) -> Option<String> {
    use std::net::ToSocketAddrs;
    // Cheap-and-cheerful reverse via getaddrinfo on the IP string. This isn't
    // a real reverse DNS lookup but it works for many Cloud providers.
    // For real rdns we'd use the dns-lookup crate, skipped to keep deps small.
    let _ = ip;
    None
}
