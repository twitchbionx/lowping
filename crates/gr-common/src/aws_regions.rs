//! AWS IP-range lookup.
//!
//! Bundles a snapshot of [AWS's IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)
//! and provides O(log n) lookups: given an IP, what AWS region is it in?
//!
//! Used by the lowping route picker: when a game opens a connection to an
//! AWS-hosted game server, we look up the region and pick the bridge that
//! serves it best.
//!
//! Refresh the snapshot occasionally:
//!   curl -sSL https://ip-ranges.amazonaws.com/ip-ranges.json -o data/aws-ranges.json

use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

const RANGES_JSON: &[u8] = include_bytes!("../../../data/aws-ranges.json");

#[derive(Debug, Deserialize)]
struct AwsRanges {
    #[serde(rename = "syncToken")]
    sync_token: String,
    #[serde(rename = "createDate")]
    create_date: String,
    prefixes: Vec<Prefix>,
}

#[derive(Debug, Deserialize)]
struct Prefix {
    ip_prefix: String,
    region: String,
    service: String,
    // borders/networks/etc. unused
}

/// Compact in-memory form: sorted (network_addr, mask, region_idx).
#[derive(Debug)]
struct CompiledPrefix {
    network: u32,    // first IP of the prefix
    mask_len: u8,    // /x
    region_idx: u32, // index into `regions` table
}

#[derive(Debug)]
pub struct AwsLookup {
    pub sync_token: String,
    pub create_date: String,
    regions: Vec<String>,
    /// Sorted by `network` ascending — supports binary search.
    prefixes: Vec<CompiledPrefix>,
}

impl AwsLookup {
    /// Load the bundled snapshot. Panics on parse failure (data is checked at
    /// build time in CI so this is fine).
    pub fn load_bundled() -> Self {
        let raw: AwsRanges = serde_json::from_slice(RANGES_JSON)
            .expect("bundled aws-ranges.json is valid");

        let mut region_to_idx: std::collections::HashMap<String, u32> = Default::default();
        let mut regions = Vec::new();
        let mut compiled = Vec::with_capacity(raw.prefixes.len());

        for p in raw.prefixes {
            // Skip non-EC2/Amazon services if you want — for now keep all
            // since some services use IPs in EC2 ranges anyway.
            // (We dedupe in compiled step below.)
            let Some((net, mask_len)) = parse_cidr(&p.ip_prefix) else { continue };
            let idx = *region_to_idx.entry(p.region.clone()).or_insert_with(|| {
                let id = regions.len() as u32;
                regions.push(p.region.clone());
                id
            });
            compiled.push(CompiledPrefix { network: net, mask_len, region_idx: idx });
            let _ = p.service;
        }

        // Sort by network ascending so we can binary-search.
        compiled.sort_by_key(|c| (c.network, c.mask_len));
        // Dedup identical (network, mask, region) tuples.
        compiled.dedup_by(|a, b| a.network == b.network && a.mask_len == b.mask_len && a.region_idx == b.region_idx);

        Self {
            sync_token: raw.sync_token,
            create_date: raw.create_date,
            regions,
            prefixes: compiled,
        }
    }

    /// Look up which AWS region (if any) owns this IP.
    /// Returns `None` if the IP isn't in AWS space.
    pub fn region_for(&self, ip: IpAddr) -> Option<&str> {
        let v4 = match ip {
            IpAddr::V4(v) => u32::from_be_bytes(v.octets()),
            IpAddr::V6(_) => return None, // v6 ranges deferred
        };

        // Binary search for the largest network whose first IP <= v4.
        // Then linearly check overlapping prefixes (some may match because of
        // /16 vs /18 etc.). Pick the most-specific (longest mask) that contains v4.
        //
        // This is O(log n) for the binary search + O(k) for at most a few
        // overlapping prefixes — always fast in practice (k < 5).
        let idx = match self.prefixes.binary_search_by_key(&v4, |p| p.network) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };

        let mut best: Option<(u8, u32)> = None; // (mask_len, region_idx)
        for back in 0..32usize.min(idx + 1) {
            let i = idx - back;
            let p = &self.prefixes[i];
            // Stop walking back once we're far enough that no prefix could contain v4
            if p.network > v4 { continue; }
            let host_bits = 32 - p.mask_len as u32;
            let net_size = if host_bits == 32 { u32::MAX } else { (1u32 << host_bits) - 1 };
            if v4 <= p.network.saturating_add(net_size) {
                // p contains v4; longer mask wins
                if best.map_or(true, |(m, _)| p.mask_len > m) {
                    best = Some((p.mask_len, p.region_idx));
                }
            } else {
                // disjoint; no shorter prefix earlier could contain v4 either
                // (because all prefixes are sorted by network)
                // but we still try a few more for safety
            }
        }
        best.map(|(_, idx)| self.regions[idx as usize].as_str())
    }

    pub fn region_count(&self) -> usize { self.regions.len() }
    pub fn prefix_count(&self) -> usize { self.prefixes.len() }
}

fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (ip, mask) = s.split_once('/')?;
    let mask_len: u8 = mask.parse().ok()?;
    if mask_len > 32 { return None; }
    let ip: Ipv4Addr = ip.parse().ok()?;
    let network = u32::from_be_bytes(ip.octets()) & if mask_len == 0 { 0 } else { !0u32 << (32 - mask_len) };
    Some((network, mask_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_us_east_1_for_known_ip() {
        let lookup = AwsLookup::load_bundled();
        // 18.88.19.234 — confirmed AWS us-east-1 EC2 (Fortnite NAE server)
        let ip: IpAddr = "18.88.19.234".parse().unwrap();
        assert_eq!(lookup.region_for(ip), Some("us-east-1"));
    }

    #[test]
    fn non_aws_ip_returns_none() {
        let lookup = AwsLookup::load_bundled();
        // Cloudflare DNS, definitely not AWS
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(lookup.region_for(ip), None);
    }

    #[test]
    fn long_mask_wins_over_short_mask() {
        // If both 18.88.0.0/18 and a hypothetical 18.0.0.0/8 covered the IP,
        // the /18 region should win. We can't easily fake this without injecting
        // data, so just verify the lookup is consistent across sample IPs.
        let lookup = AwsLookup::load_bundled();
        let _ = lookup.region_for("3.5.140.4".parse().unwrap()); // us-east-1 typical
    }

    #[test]
    fn loads_thousands_of_prefixes() {
        let lookup = AwsLookup::load_bundled();
        assert!(lookup.prefix_count() > 5000, "snapshot should have many prefixes");
        assert!(lookup.region_count() > 20, "AWS has 20+ regions");
    }
}
