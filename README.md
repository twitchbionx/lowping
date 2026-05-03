# lowping

A Windows game traffic optimizer — open-source, BYO-bridge, no telemetry.

## What it does

Intercepts your game's TCP/UDP traffic at the kernel (Windows Filtering Platform)
and routes it through one or more relay servers ("bridges") that you (or someone you
trust) operate. Multi-path send + Reed-Solomon FEC eliminates packet loss without
adding latency. The intent is to provide what commercial services like ExitLag /
NoPing / WTFast offer, with three differences: it's open-source, it doesn't lock
your machine to an account, and you can run your own infrastructure.

**Status:** early development. Nothing works yet.

## Architecture (one paragraph)

A small WFP callout driver (`grfilter.sys`) intercepts outbound TCP/UDP connections
and asks a userland Rust service (`grclient`) what to do. The service decides based
on a rule engine + game catalog. Selected connections are tunneled to one or more
bridges (`grbridge`) — same Rust binary, different mode — running on VPSes you
configure. Tunnel uses XChaCha20-Poly1305 with optional Reed-Solomon FEC and
multi-path duplication for loss-free delivery. UI is a small Tauri app.

See `docs/architecture.md` and `docs/protocol.md` for details.

## Building

You'll need:

- Windows 10/11 x64 (target)
- [Rust](https://rustup.rs/) 1.85+
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk)
  (only if building the kernel driver)
- Node.js 20+ (only if building the UI)

```bash
# Build all userland crates (works cross-platform):
cargo build --workspace --release

# Build just the bridge (Linux):
cargo build --release -p gr-bridge --target x86_64-unknown-linux-gnu

# Driver: see driver/README.md for WDK setup
```

## Running a bridge

A bridge needs a public IP and a UDP port open. Single static binary:

```bash
# On any Linux VPS (Hetzner, OVH, Vultr — €4.50/mo is plenty):
curl -L https://github.com/twitchbionx/lowping/releases/latest/download/grbridge-x86_64-linux > grbridge
chmod +x grbridge
./grbridge --listen 0.0.0.0:51820 --keys-file keys.toml
```

`keys.toml` lists allowed client public keys. Bridges authenticate clients via
Ed25519; no central auth server.

## Running the client

```bash
# After installing (Phase 5+ will have an installer):
lowping  # opens the UI
```

The UI walks you through adding your first bridge.

## Why not just use [ExitLag/NoPing/WTFast]?

You should — if their pricing and trust model work for you. lowping exists for
people who:

- want to operate their own relay infrastructure
- don't want their AV name, firewall configuration, and hardware ID exfiltrated
  on every login
- prefer auditable open-source software running with kernel privileges
- want to use it on platforms / games the commercial options ignore

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Pre-MVP. Contributions welcome but expect churn. See `docs/architecture.md` for
the design and `crates/gr-protocol/src/lib.rs` for where the protocol is defined.
