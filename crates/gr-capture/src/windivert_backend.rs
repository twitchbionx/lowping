//! WinDivert-backed packet capture + DNAT for Windows.
//!
//! ## How it works
//!
//! For each captured packet (per filter expression in [`build_filter`]):
//!
//! - **Outbound** matching a rule:
//!   - Save `src_port -> (orig_dst_ip, orig_dst_port)` in the flow table.
//!   - Rewrite `dst_ip := redirect_to_ip` and `dst_port := redirect_to_port`.
//!   - Recompute IP+UDP/TCP checksums.
//!   - Re-inject.
//!
//! - **Inbound** from the local target (response coming back from grclient):
//!   - Look up flow by `dst_port` (which equals the game's original `src_port`).
//!   - Rewrite `src_ip := orig_dst_ip` and `src_port := orig_dst_port`.
//!   - Recompute checksums.
//!   - Re-inject.
//!
//! Result: the game's socket sees responses as if they came directly from the
//! original game server. Game has no idea anything was rewritten.

use crate::{CaptureError, Protocol, RedirectRule, RedirectStats, Redirector, Result};
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

/// Per-flow NAT entry. Key is the game's source port.
#[derive(Debug, Clone, Copy)]
struct FlowEntry {
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
    last_seen: Instant,
}

pub struct WinDivertCapture {
    rules: Vec<RedirectRule>,
    flows: Arc<RwLock<HashMap<u16, FlowEntry>>>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    flow_idle: Duration,
}

#[derive(Default)]
struct Stats {
    outbound_redirected: AtomicU64,
    inbound_rewritten: AtomicU64,
    dropped_unparseable: AtomicU64,
}

impl WinDivertCapture {
    pub fn new(rules: Vec<RedirectRule>) -> Self {
        Self {
            rules,
            flows: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Stats::default()),
            running: Arc::new(AtomicBool::new(false)),
            handle: parking_lot::Mutex::new(None),
            flow_idle: Duration::from_secs(120),
        }
    }

    fn build_filter(&self) -> Result<String> {
        if self.rules.is_empty() {
            return Err(CaptureError::Other("no rules configured".into()));
        }
        let mut clauses = Vec::new();
        for rule in &self.rules {
            let proto = match rule.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            let dst_ip = match rule.dst_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => continue,
            };
            let local = match rule.redirect_to_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => continue,
            };
            clauses.push(format!(
                "({proto} and outbound and ip.DstAddr == {dst_ip} and {proto}.DstPort >= {lo} and {proto}.DstPort <= {hi})",
                lo = rule.dst_port_lo,
                hi = rule.dst_port_hi,
            ));
            clauses.push(format!(
                "({proto} and inbound and ip.SrcAddr == {local} and {proto}.SrcPort == {port})",
                port = rule.redirect_to_port,
            ));
        }
        Ok(clauses.join(" or "))
    }
}

impl Redirector for WinDivertCapture {
    fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let filter = self.build_filter()?;
        tracing::info!(filter = %filter, "WinDivert filter compiled");

        let rules = self.rules.clone();
        let flows = self.flows.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let flow_idle = self.flow_idle;

        let handle = std::thread::Builder::new()
            .name("windivert-capture".into())
            .spawn(move || {
                if let Err(e) = run_capture_loop(filter, rules, flows, stats, running, flow_idle) {
                    tracing::error!(error = ?e, "windivert capture loop exited");
                }
            })
            .map_err(|e| CaptureError::Other(format!("spawn: {e}")))?;

        *self.handle.lock() = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> RedirectStats {
        let flows = self.flows.read();
        RedirectStats {
            outbound_redirected: self.stats.outbound_redirected.load(Ordering::Relaxed),
            inbound_rewritten: self.stats.inbound_rewritten.load(Ordering::Relaxed),
            dropped_unparseable: self.stats.dropped_unparseable.load(Ordering::Relaxed),
            active_flows: flows.len() as u64,
        }
    }
}

// =============================================================================
// Capture loop
// =============================================================================

const IPV4_VERSION: u8 = 4;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn run_capture_loop(
    filter: String,
    rules: Vec<RedirectRule>,
    flows: Arc<RwLock<HashMap<u16, FlowEntry>>>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    flow_idle: Duration,
) -> Result<()> {
    let divert = WinDivert::network(&filter, 0, Default::default())
        .map_err(|e| CaptureError::DriverOpen(e.to_string()))?;
    tracing::info!("WinDivert opened, capture running");

    let mut buffer = [0u8; 65536];
    let mut last_reap = Instant::now();

    while running.load(Ordering::Relaxed) {
        // Periodic flow expiry
        if last_reap.elapsed() > Duration::from_secs(15) {
            reap_flows(&flows, flow_idle);
            last_reap = Instant::now();
        }

        let mut packet = match divert.recv(&mut buffer) {
            Ok(p) => p,
            Err(e) => {
                tracing::trace!(error = ?e, "recv error");
                continue;
            }
        };

        let outbound = packet.address.outbound();
        let data = packet.data.to_vec(); // own it so we can modify

        let modified = match process_packet(&data, outbound, &rules, &flows) {
            Some(m) => m,
            None => {
                stats.dropped_unparseable.fetch_add(1, Ordering::Relaxed);
                // Pass through unmodified — return original packet
                if let Err(e) = divert.send(&packet) {
                    tracing::trace!(error = ?e, "passthrough send failed");
                }
                continue;
            }
        };

        // Replace packet data with our modified version
        packet.data = Cow::Owned(modified);
        if let Err(e) = packet.recalculate_checksums(ChecksumFlags::default()) {
            tracing::warn!(error = ?e, "checksum recalc failed");
            continue;
        }

        if outbound {
            stats.outbound_redirected.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.inbound_rewritten.fetch_add(1, Ordering::Relaxed);
        }

        if let Err(e) = divert.send(&packet) {
            tracing::warn!(error = ?e, "send failed");
        }
    }

    Ok(())
}

/// Parse + apply DNAT to a single packet. Returns the modified bytes (or None
/// if we couldn't make sense of the packet — caller should pass-through).
///
/// IPv4 only for now. Assumes no IP options (IHL == 5, fixed 20-byte header).
fn process_packet(
    data: &[u8],
    outbound: bool,
    rules: &[RedirectRule],
    flows: &Arc<RwLock<HashMap<u16, FlowEntry>>>,
) -> Option<Vec<u8>> {
    if data.len() < 28 { return None; } // need at least IP+UDP headers
    let version = data[0] >> 4;
    if version != IPV4_VERSION { return None; }
    let ihl = (data[0] & 0x0F) as usize;
    if ihl < 5 { return None; }
    let ip_header_len = ihl * 4;
    if data.len() < ip_header_len + 8 { return None; }

    let proto = data[9];
    if proto != PROTO_TCP && proto != PROTO_UDP { return None; }

    let mut out = data.to_vec();

    let src_ip = Ipv4Addr::new(out[12], out[13], out[14], out[15]);
    let dst_ip = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
    let src_port = u16::from_be_bytes([out[ip_header_len], out[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([out[ip_header_len + 2], out[ip_header_len + 3]]);

    if outbound {
        // Find matching rule
        let rule = rules.iter().find(|r| {
            let want_proto = match r.protocol {
                Protocol::Tcp => PROTO_TCP,
                Protocol::Udp => PROTO_UDP,
            };
            proto == want_proto
                && IpAddr::V4(dst_ip) == r.dst_ip
                && dst_port >= r.dst_port_lo
                && dst_port <= r.dst_port_hi
        })?;

        let new_dst_ip = match rule.redirect_to_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        };

        // Save flow entry for the return path
        flows.write().insert(src_port, FlowEntry {
            orig_dst_ip: dst_ip,
            orig_dst_port: dst_port,
            last_seen: Instant::now(),
        });

        // Rewrite dst
        let dst_octets = new_dst_ip.octets();
        out[16..20].copy_from_slice(&dst_octets);
        out[ip_header_len + 2..ip_header_len + 4]
            .copy_from_slice(&rule.redirect_to_port.to_be_bytes());

        tracing::trace!(
            src_port,
            from = %dst_ip, from_port = dst_port,
            to = %new_dst_ip, to_port = rule.redirect_to_port,
            "outbound redirect"
        );
        Some(out)
    } else {
        // Inbound: look up flow by dst_port (which is the game's original src_port)
        let entry = {
            let mut w = flows.write();
            let e = w.get(&dst_port).copied()?;
            // Refresh idle timer
            if let Some(slot) = w.get_mut(&dst_port) {
                slot.last_seen = Instant::now();
            }
            e
        };

        // Rewrite src to original game server
        let src_octets = entry.orig_dst_ip.octets();
        out[12..16].copy_from_slice(&src_octets);
        out[ip_header_len..ip_header_len + 2]
            .copy_from_slice(&entry.orig_dst_port.to_be_bytes());

        tracing::trace!(
            game_port = dst_port,
            response_now_appears_from = %entry.orig_dst_ip,
            from_port = entry.orig_dst_port,
            "inbound rewrite"
        );
        let _ = src_ip; // silence unused
        Some(out)
    }
}

fn reap_flows(flows: &Arc<RwLock<HashMap<u16, FlowEntry>>>, idle: Duration) {
    let cutoff = Instant::now() - idle;
    let mut w = flows.write();
    let before = w.len();
    w.retain(|_, e| e.last_seen >= cutoff);
    let dropped = before - w.len();
    if dropped > 0 {
        tracing::debug!(dropped, "reaped idle flows");
    }
}
