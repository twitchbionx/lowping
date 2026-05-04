//! WinDivert-backed packet capture + DNAT for Windows.
//!
//! ## Two operating modes
//!
//! 1. **Legacy fixed-rule mode**: pass `Vec<RedirectRule>` to
//!    [`WinDivertCapture::with_rules`]. Filter targets specific dst_ip+port
//!    ranges. Simple but no auto bridge selection.
//!
//! 2. **Smart-routing mode**: pass any `RouteResolver` impl to
//!    [`WinDivertCapture::with_resolver`]. Filter is broad ("all UDP outbound
//!    not to bridges"); per-packet decision via the resolver. Use with
//!    `gr_client::router::Router` for live multi-bridge picking.
//!
//! ## NAT model (both modes)
//!
//! Outbound match → save (src_port, orig_dst, redirect_target) flow entry,
//! rewrite dst, recompute checksums, re-inject. Inbound from a redirect
//! target → look up flow by dst_port, rewrite src back to the original game
//! server so the game's socket sees a normal response.

use crate::{
    CaptureError, FixedResolver, Protocol, RedirectRule, RedirectStats, Redirector, Result,
    RouteAction, RouteResolver,
};
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    /// The (ip, port) we rewrote outbound traffic to. Inbound packets from
    /// this address are the responses we need to rewrite back.
    redirect_target: SocketAddr,
    last_seen: Instant,
}

/// All [`SocketAddr`]s our redirector might rewrite TO. Used to build the
/// inbound half of the WinDivert filter expression.
type RedirectTargets = Vec<SocketAddr>;

pub struct WinDivertCapture {
    resolver: Arc<dyn RouteResolver>,
    /// IPs/ports our resolver might rewrite TO. Required up-front for the
    /// inbound side of the WinDivert filter.
    redirect_targets: RedirectTargets,
    /// Bridge endpoints we MUST NOT capture (we'd loop forever).
    bridge_endpoints: Vec<SocketAddr>,
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
    /// Legacy: build from a fixed rule list.
    pub fn new(rules: Vec<RedirectRule>) -> Self {
        Self::with_rules(rules, vec![])
    }

    /// Build with explicit rules and an explicit bridge-endpoint exclusion list
    /// (so we don't capture our own tunnel traffic).
    pub fn with_rules(rules: Vec<RedirectRule>, bridge_endpoints: Vec<SocketAddr>) -> Self {
        let targets = rules
            .iter()
            .map(|r| SocketAddr::new(r.redirect_to_ip, r.redirect_to_port))
            .collect();
        Self {
            resolver: Arc::new(FixedResolver(rules)),
            redirect_targets: targets,
            bridge_endpoints,
            flows: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Stats::default()),
            running: Arc::new(AtomicBool::new(false)),
            handle: parking_lot::Mutex::new(None),
            flow_idle: Duration::from_secs(120),
        }
    }

    /// Smart mode: any resolver, with the set of (ip, port) addresses it might
    /// rewrite TO and the bridge endpoints to exclude from capture.
    pub fn with_resolver(
        resolver: Arc<dyn RouteResolver>,
        redirect_targets: Vec<SocketAddr>,
        bridge_endpoints: Vec<SocketAddr>,
    ) -> Self {
        Self {
            resolver,
            redirect_targets,
            bridge_endpoints,
            flows: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Stats::default()),
            running: Arc::new(AtomicBool::new(false)),
            handle: parking_lot::Mutex::new(None),
            flow_idle: Duration::from_secs(120),
        }
    }

    fn build_filter(&self) -> Result<String> {
        if self.redirect_targets.is_empty() {
            return Err(CaptureError::Other(
                "no redirect targets — at least one is needed to capture inbound responses"
                    .into(),
            ));
        }
        // Outbound: any UDP outbound, EXCEPT to bridge endpoints (avoid loop)
        // and EXCEPT to our redirect targets themselves (avoid loop).
        let mut excludes: Vec<String> = Vec::new();
        for ep in &self.bridge_endpoints {
            if let IpAddr::V4(v4) = ep.ip() {
                excludes.push(format!("ip.DstAddr == {v4}"));
            }
        }
        for tgt in &self.redirect_targets {
            if let IpAddr::V4(v4) = tgt.ip() {
                excludes.push(format!("ip.DstAddr == {v4}"));
            }
        }
        let exclude_clause = if excludes.is_empty() {
            String::new()
        } else {
            format!(" and not ({})", excludes.join(" or "))
        };

        // Inbound: only packets coming from our redirect targets (responses
        // from grclient that need src-rewriting).
        let inbound_targets: Vec<String> = self
            .redirect_targets
            .iter()
            .filter_map(|t| match t.ip() {
                IpAddr::V4(v4) => Some(format!(
                    "(ip.SrcAddr == {v4} and udp.SrcPort == {})",
                    t.port()
                )),
                IpAddr::V6(_) => None,
            })
            .collect();
        let inbound_clause = inbound_targets.join(" or ");

        Ok(format!(
            "(udp and outbound{exclude_clause}) or (udp and inbound and ({inbound_clause}))"
        ))
    }
}

impl WinDivertCapture {
    /// Look up the original game-server destination for a captured flow.
    ///
    /// When the capture loop rewrites an outbound packet from
    /// `(game_src_ip, game_src_port) → (orig_dst_ip, orig_dst_port)` to point
    /// at our local listener, it records the original destination keyed by
    /// `game_src_port`. The local listener can then call this to discover where
    /// the game *meant* to send each datagram, and tunnel it to the right place.
    pub fn flow_origin(&self, game_src_port: u16) -> Option<SocketAddr> {
        let flows = self.flows.read();
        let e = flows.get(&game_src_port)?;
        Some(SocketAddr::new(IpAddr::V4(e.orig_dst_ip), e.orig_dst_port))
    }

    /// All currently-tracked (game_src_port, original_dest) pairs.
    /// Useful for debugging / observability.
    pub fn active_flows(&self) -> Vec<(u16, SocketAddr)> {
        self.flows
            .read()
            .iter()
            .map(|(p, e)| (*p, SocketAddr::new(IpAddr::V4(e.orig_dst_ip), e.orig_dst_port)))
            .collect()
    }
}

impl Redirector for WinDivertCapture {
    fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let filter = self.build_filter()?;
        tracing::info!(filter_chars = filter.len(), "WinDivert filter compiled");
        tracing::debug!(filter = %filter, "filter expression");

        let resolver = self.resolver.clone();
        let flows = self.flows.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let flow_idle = self.flow_idle;

        let handle = std::thread::Builder::new()
            .name("windivert-capture".into())
            .spawn(move || {
                if let Err(e) = run_capture_loop(filter, resolver, flows, stats, running, flow_idle) {
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
    resolver: Arc<dyn RouteResolver>,
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
        let data = packet.data.to_vec();

        let modified = match process_packet(&data, outbound, &*resolver, &flows) {
            Some(m) => m,
            None => {
                stats.dropped_unparseable.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = divert.send(&packet) {
                    tracing::trace!(error = ?e, "passthrough send failed");
                }
                continue;
            }
        };

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
fn process_packet(
    data: &[u8],
    outbound: bool,
    resolver: &dyn RouteResolver,
    flows: &Arc<RwLock<HashMap<u16, FlowEntry>>>,
) -> Option<Vec<u8>> {
    if data.len() < 28 {
        return None;
    }
    let version = data[0] >> 4;
    if version != IPV4_VERSION {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }
    let ip_header_len = ihl * 4;
    if data.len() < ip_header_len + 8 {
        return None;
    }

    let proto = data[9];
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let proto_enum = if proto == PROTO_TCP { Protocol::Tcp } else { Protocol::Udp };

    let mut out = data.to_vec();
    let dst_ip = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
    let src_port = u16::from_be_bytes([out[ip_header_len], out[ip_header_len + 1]]);
    let dst_port = u16::from_be_bytes([out[ip_header_len + 2], out[ip_header_len + 3]]);

    if outbound {
        let dst = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        let action = resolver.resolve(dst, proto_enum);
        let RouteAction::RewriteTo(target) = action else {
            return None; // passthrough — caller will send the original packet unchanged
        };
        let new_dst_ip = match target.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        };

        flows.write().insert(
            src_port,
            FlowEntry {
                orig_dst_ip: dst_ip,
                orig_dst_port: dst_port,
                redirect_target: target,
                last_seen: Instant::now(),
            },
        );

        let dst_octets = new_dst_ip.octets();
        out[16..20].copy_from_slice(&dst_octets);
        out[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&target.port().to_be_bytes());

        tracing::trace!(
            src_port,
            from = %dst_ip, from_port = dst_port,
            to = %new_dst_ip, to_port = target.port(),
            "outbound rewrite"
        );
        Some(out)
    } else {
        // Inbound: src is one of our redirect targets; dst_port is the game's original src_port
        let entry = {
            let mut w = flows.write();
            let e = w.get(&dst_port).copied()?;
            if let Some(slot) = w.get_mut(&dst_port) {
                slot.last_seen = Instant::now();
            }
            e
        };

        let src_octets = entry.orig_dst_ip.octets();
        out[12..16].copy_from_slice(&src_octets);
        out[ip_header_len..ip_header_len + 2]
            .copy_from_slice(&entry.orig_dst_port.to_be_bytes());

        tracing::trace!(
            game_port = dst_port,
            response_now_appears_from = %entry.orig_dst_ip,
            from_port = entry.orig_dst_port,
            redirect_was_to = %entry.redirect_target,
            "inbound rewrite"
        );
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
