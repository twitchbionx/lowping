//! Smart route picker.
//!
//! For each new outbound flow `(dest_ip, dest_port)`, decide whether to:
//!   1. Pass it through directly (game's natural ISP path is best), or
//!   2. Tunnel it via Bridge A, B, C... (one of the configured bridges has a
//!      better total path)
//!
//! ## Decision algorithm (current)
//!
//! For each candidate path:
//!   - **Direct**:  client_to_dest_rtt   (measured live with ICMP ping)
//!   - **Via bridge B**: client_to_bridge_rtt + bridge_to_region_rtt
//!     where `bridge_to_region_rtt` is from the bridge's published ping table
//!     (B's RTT to AWS region X, where X is where the destination IP lives)
//!
//! Pick the lowest. With a small hysteresis margin (default 2ms) to avoid
//! flapping when paths are within noise of each other; ties go to direct
//! (because no tunnel = lower CPU + no NAT state).
//!
//! ## Caching
//!
//! Decisions are cached per-destination IP. Re-evaluated every
//! `reroute_interval_secs` (default 60s) to pick up route quality changes
//! (an ISP that has a bad day, a bridge that came back online, etc.).

use gr_common::aws_regions::AwsLookup;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEntry {
    /// Stable name used in logs and config references.
    pub name: String,
    /// Where to send tunnel traffic.
    pub endpoint: SocketAddr,
    pub bridge_x25519_pubkey_hex: String,
    pub license_token: String,
    /// Local UDP port grclient listens on for redirected traffic via this bridge.
    /// Each bridge needs its own port so capture rules can route by destination.
    pub listen_port: u16,
    /// Bridge → AWS region RTT (ms). The bridge measures these periodically
    /// and publishes them via the directory; for now you can hardcode here.
    #[serde(default)]
    pub region_rtt_ms: HashMap<String, f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Don't capture — let the OS handle it natively.
    Direct,
    /// Tunnel via this bridge (index into the router's bridges Vec).
    ViaBridge(usize),
}

#[derive(Debug, Clone, Copy)]
struct Decision {
    route: Route,
    decided_at: Instant,
    direct_rtt_ms: f64,
    via_bridge_rtt_ms: f64,
}

/// Stateful route picker. Holds the bridge directory + AWS lookup + decision cache.
pub struct Router {
    bridges: Vec<BridgeEntry>,
    /// Client's measured RTT to each bridge. Updated periodically.
    client_to_bridge_ms: RwLock<HashMap<String, f64>>,
    aws: AwsLookup,
    cache: RwLock<HashMap<IpAddr, Decision>>,
    /// Hysteresis: only choose a bridge if it beats direct by this margin (ms).
    margin_ms: f64,
    /// Re-evaluate cached decisions older than this.
    reroute_interval: Duration,
}

impl Router {
    pub fn new(bridges: Vec<BridgeEntry>) -> Self {
        Self {
            bridges,
            client_to_bridge_ms: RwLock::new(HashMap::new()),
            aws: AwsLookup::load_bundled(),
            cache: RwLock::new(HashMap::new()),
            margin_ms: 2.0,
            reroute_interval: Duration::from_secs(60),
        }
    }

    pub fn bridges(&self) -> &[BridgeEntry] {
        &self.bridges
    }

    /// Update measured RTT to a bridge. Called by the latency-probe task.
    pub fn record_client_to_bridge(&self, bridge_name: &str, rtt_ms: f64) {
        self.client_to_bridge_ms
            .write()
            .insert(bridge_name.to_string(), rtt_ms);
    }

    /// Pick a route for this destination. Uses cache when fresh; otherwise
    /// computes a fresh decision based on currently-known measurements.
    ///
    /// `direct_rtt_ms` is the client's measured RTT to `dest.ip()`. Pass
    /// `f64::INFINITY` if not yet measured (caller should kick off a measure
    /// task and call again later).
    pub fn pick(&self, dest: SocketAddr, direct_rtt_ms: f64) -> Route {
        // Cache hit?
        if let Some(d) = self.cache.read().get(&dest.ip()) {
            if d.decided_at.elapsed() < self.reroute_interval {
                return d.route;
            }
        }

        let region = self.aws.region_for(dest.ip());

        // Compute via-bridge candidates
        let mut best_bridge: Option<(usize, f64)> = None;
        let pings = self.client_to_bridge_ms.read();
        for (idx, b) in self.bridges.iter().enumerate() {
            let Some(&to_b) = pings.get(&b.name) else { continue };
            let from_b = match region {
                Some(r) => match b.region_rtt_ms.get(r) {
                    Some(&v) => v,
                    None => continue, // bridge has no path measurement to this region
                },
                None => continue, // unknown region — can't estimate bridge path
            };
            let total = to_b + from_b;
            if best_bridge.map_or(true, |(_, t)| total < t) {
                best_bridge = Some((idx, total));
            }
        }
        drop(pings);

        let (route, via_total) = match best_bridge {
            Some((idx, total)) if total + self.margin_ms < direct_rtt_ms => {
                (Route::ViaBridge(idx), total)
            }
            Some((_, total)) => (Route::Direct, total),
            None => (Route::Direct, f64::INFINITY),
        };

        let decision = Decision {
            route,
            decided_at: Instant::now(),
            direct_rtt_ms,
            via_bridge_rtt_ms: via_total,
        };
        self.cache.write().insert(dest.ip(), decision);

        if matches!(route, Route::ViaBridge(_)) {
            tracing::info!(
                dest = %dest, region = ?region,
                direct_ms = direct_rtt_ms, via_ms = via_total,
                "→ route via bridge {}", self.bridges[match route { Route::ViaBridge(i) => i, _ => 0 }].name
            );
        } else {
            tracing::debug!(
                dest = %dest, region = ?region,
                direct_ms = direct_rtt_ms, best_via_ms = via_total,
                "→ direct"
            );
        }

        route
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nj_bridge() -> BridgeEntry {
        let mut rtt = HashMap::new();
        rtt.insert("us-east-1".into(), 5.0);
        rtt.insert("us-east-2".into(), 12.0);
        rtt.insert("us-west-2".into(), 70.0);
        BridgeEntry {
            name: "nj".into(),
            endpoint: "45.77.158.154:52820".parse().unwrap(),
            bridge_x25519_pubkey_hex: "00".repeat(32),
            license_token: "tok".into(),
            listen_port: 9700,
            region_rtt_ms: rtt,
        }
    }

    fn dallas_bridge() -> BridgeEntry {
        let mut rtt = HashMap::new();
        rtt.insert("us-east-1".into(), 1.5);
        rtt.insert("us-east-2".into(), 2.5);
        rtt.insert("us-west-2".into(), 30.0);
        BridgeEntry {
            name: "dallas".into(),
            endpoint: "149.28.240.106:52820".parse().unwrap(),
            bridge_x25519_pubkey_hex: "00".repeat(32),
            license_token: "tok".into(),
            listen_port: 9701,
            region_rtt_ms: rtt,
        }
    }

    #[test]
    fn picks_direct_when_direct_is_fastest() {
        let r = Router::new(vec![nj_bridge(), dallas_bridge()]);
        // Pretend client→NJ=35, client→Dallas=22
        r.record_client_to_bridge("nj", 35.0);
        r.record_client_to_bridge("dallas", 22.0);

        // Fortnite NA-East server (us-east-1, direct=18ms from client)
        let dest: SocketAddr = "18.88.19.234:22222".parse().unwrap();
        let route = r.pick(dest, 18.0);
        // Best bridge: dallas (22 + 1.5 = 23.5). Direct is 18. Direct wins.
        assert_eq!(route, Route::Direct);
    }

    #[test]
    fn picks_bridge_when_direct_is_slower() {
        let r = Router::new(vec![nj_bridge(), dallas_bridge()]);
        r.record_client_to_bridge("nj", 35.0);
        r.record_client_to_bridge("dallas", 22.0);

        // Same dest but pretend client's direct path is bad today (40ms)
        let dest: SocketAddr = "18.88.19.234:22222".parse().unwrap();
        let route = r.pick(dest, 40.0);
        // Dallas: 22 + 1.5 = 23.5. NJ: 35 + 5 = 40. Dallas wins, beats direct (40)
        assert_eq!(route, Route::ViaBridge(1));
    }

    #[test]
    fn no_bridge_chosen_when_within_margin() {
        let r = Router::new(vec![dallas_bridge()]);
        r.record_client_to_bridge("dallas", 22.0);
        // Direct = 24 (just barely worse than bridge total 23.5)
        // Margin is 2ms → 23.5 + 2 = 25.5 > 24 → direct wins
        let dest: SocketAddr = "18.88.19.234:22222".parse().unwrap();
        assert_eq!(r.pick(dest, 24.0), Route::Direct);
    }

    #[test]
    fn picks_correct_bridge_per_region() {
        let r = Router::new(vec![nj_bridge(), dallas_bridge()]);
        r.record_client_to_bridge("nj", 35.0);
        r.record_client_to_bridge("dallas", 22.0);

        // For us-west-2 destination (some 44.x.x.x), NJ has 70ms path, Dallas 30ms
        // Direct = bad (60ms)
        // NJ:     35 + 70 = 105
        // Dallas: 22 + 30 = 52
        // Dallas wins (and beats direct 60)
        let dest: SocketAddr = "44.232.10.1:7777".parse().unwrap();
        assert_eq!(r.pick(dest, 60.0), Route::ViaBridge(1)); // dallas (idx 1)
    }

    #[test]
    fn unknown_region_falls_through_to_direct() {
        let r = Router::new(vec![dallas_bridge()]);
        r.record_client_to_bridge("dallas", 22.0);
        // 1.1.1.1 is Cloudflare, not in AWS — we have no path estimate
        let dest: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(r.pick(dest, 18.0), Route::Direct);
    }

    #[test]
    fn cache_returns_same_decision_within_interval() {
        let r = Router::new(vec![dallas_bridge()]);
        r.record_client_to_bridge("dallas", 22.0);
        let dest: SocketAddr = "18.88.19.234:22222".parse().unwrap();
        let r1 = r.pick(dest, 40.0);
        // Even with a different direct_rtt the second call should return cached
        let r2 = r.pick(dest, 5.0);
        assert_eq!(r1, r2);
    }
}
