//! WinDivert-backed capture for Windows.
//!
//! Phase 3a: opens a WinDivert handle on the Network layer, captures packets
//! matching configured rules, performs DNAT to redirect game traffic to the
//! local grclient port, and re-injects.
//!
//! ## NAT model
//!
//! For each outbound packet matching a [`RedirectRule`]:
//!   `(src_port) -> (orig_dst_ip, orig_dst_port)` is saved in a flow table.
//! The packet's destination is rewritten to `(redirect_to_ip, redirect_to_port)`.
//!
//! For each inbound packet from `(127.0.0.1, redirect_to_port) -> (anything, src_port)`:
//!   Look up `src_port` in the flow table.
//!   Rewrite source to `(orig_dst_ip, orig_dst_port)` so the game's socket
//!   sees the response as coming from the real server.
//!
//! Flow entries expire after `flow_idle_secs` (default 120s).

use crate::{CaptureError, Protocol, RedirectRule, RedirectStats, Redirector, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

    /// Build a WinDivert filter expression from our rules.
    /// We capture: outbound packets matching any rule's (dst_ip, dst_port_range)
    /// AND inbound packets coming back from (127.0.0.1, redirect_to_port).
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
                IpAddr::V6(_) => continue, // v6 deferred
            };
            let local = match rule.redirect_to_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => continue,
            };
            // Outbound: matches the game-facing direction
            clauses.push(format!(
                "({proto} and outbound and ip.DstAddr == {dst_ip} and {proto}.DstPort >= {lo} and {proto}.DstPort <= {hi})",
                lo = rule.dst_port_lo,
                hi = rule.dst_port_hi,
            ));
            // Inbound: response from grclient back to the game
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
            return Ok(()); // already running
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
                if let Err(e) = run_capture_loop(filter, rules, flows.clone(), stats, running.clone(), flow_idle) {
                    tracing::error!(error = ?e, "windivert capture loop exited");
                }
            })
            .map_err(|e| CaptureError::Other(format!("spawn: {e}")))?;

        *self.handle.lock() = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        // The capture loop will notice on its next iteration. We don't join
        // to avoid blocking — Windows may keep WinDivertRecv blocked for
        // up to a few seconds before returning.
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

fn run_capture_loop(
    _filter: String,
    _rules: Vec<RedirectRule>,
    _flows: Arc<RwLock<HashMap<u16, FlowEntry>>>,
    _stats: Arc<Stats>,
    _running: Arc<AtomicBool>,
    _flow_idle: Duration,
) -> Result<()> {
    // PHASE 3a STEP 1: Open WinDivert handle.
    //
    // Pseudocode (using windivert crate's WinDivert::network):
    //
    //   let mut wd = WinDivert::network(&filter, 0, WinDivertFlags::default())
    //       .map_err(|e| CaptureError::DriverOpen(e.to_string()))?;
    //
    //   let mut buf = vec![0u8; 65536];
    //   while running.load(Ordering::Relaxed) {
    //       let pkt = match wd.recv(&mut buf) {
    //           Ok(p) => p,
    //           Err(_) => continue,
    //       };
    //       // 1. parse IPv4 header — get protocol, src/dst IP
    //       // 2. parse TCP/UDP header — get src/dst port
    //       // 3. determine direction from pkt.address.outbound()
    //       // 4. if outbound matching rule: add flow entry, rewrite dst, recompute checksum, send
    //       // 5. if inbound from local: look up flow by dst_port, rewrite src, recompute checksum, send
    //   }
    //
    // The 0.7.0-beta.4 windivert crate API is still settling; the stable
    // pattern is: build a WinDivertBuilder, call .build(), then loop on .recv()/.send().
    //
    // Phase 3a implementation lands in the next commit. For now this is a
    // compilable stub so the trait + integration are in place.
    Err(CaptureError::Other(
        "WinDivert capture loop not yet implemented — see TODO in source".into(),
    ))
}
