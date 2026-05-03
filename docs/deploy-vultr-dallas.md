# Deploying a lowping bridge on Vultr (Dallas)

Step-by-step to get your first bridge online. ~15 minutes if you're paying
attention. Targets **Vultr High Frequency in Dallas** (best Vultr option for
Fortnite NA-Central since Fortnite NAC servers are in Dallas).

## What you'll have at the end

- A `$6/mo` VPS in Vultr Dallas running the lowping bridge as a systemd service
- The backend (directory + license issuance) running on the same box on `:8080`
- An `ufw` firewall locked down to just `:22` (SSH), `:8080` (HTTPS-fronted by
  Cloudflare later), `:51820/udp` (bridge tunnel)
- Systemd hardening on both daemons (sandboxed, no new privileges, etc.)

---

## 1. Provision the VPS

In the Vultr dashboard:

1. **Cloud Compute → High Frequency**
2. Location: **Dallas**
3. Image: **Ubuntu 24.04 LTS x64**
4. Plan: **$6/mo** (1 vCPU / 1 GB / 32 GB SSD / 2 TB transfer)
5. **Add SSH Keys**: select yours (if it's not in Vultr already, paste your
   `~/.ssh/id_ed25519.pub`). Don't deploy without an SSH key — password auth
   will be disabled by the install script.
6. Skip auto-backups (save $1.20/mo).
7. **Hostname**: `bridge-dal-1`
8. Deploy

Wait ~60 seconds. Note the **public IPv4** that appears.

## 2. SSH in

```bash
ssh root@<your-bridge-ip>
```

Verify it's the right box (`hostname` should be `bridge-dal-1`).

## 3. Run the bootstrap script

This installs Rust, builds `grbridge`, creates a service user, sets up systemd,
opens the firewall, and generates an X25519 keypair.

```bash
curl -L https://raw.githubusercontent.com/twitchbionx/lowping/main/deploy/install-bridge.sh \
  | bash
```

Takes ~5 minutes (compiling Rust). When it finishes you'll see the
**X25519 public key** for this bridge — copy it. You'll need it on the client
side and to register the bridge in the backend's directory.

## 4. Install + configure the backend (on the same box for MVP)

Same machine for now — split later if you want.

```bash
# clone
git clone --depth 1 https://github.com/twitchbionx/lowping.git /tmp/lowping
cd /tmp/lowping

# build
cargo build --release -p gr-backend

# install binary + service file
install -m 0755 target/release/grbackend /usr/local/bin/grbackend
install -m 0644 deploy/systemd/grbackend.service /etc/systemd/system/grbackend.service

# create user
useradd --system --no-create-home --shell /usr/sbin/nologin grbackend

# generate Ed25519 backend key
grbackend gen-key
# Copy both lines — the secret goes in backend.toml, the pubkey goes in
# bridge.toml AND every client's config (so they verify directories + tokens).

# create config
install -m 0640 -o grbackend -g grbackend deploy/backend.toml.example /etc/lowping/backend.toml

# Edit /etc/lowping/backend.toml:
#   - paste backend_seckey_hex from gen-key output
#   - set listen = "0.0.0.0:8080"
#   - in [[bridges]], set:
#       endpoint = "<this-vps-public-ip>:51820"
#       pubkey_hex = "<x25519 pubkey from grbridge gen-key earlier>"
nano /etc/lowping/backend.toml

# allow port 8080 in firewall
ufw allow 8080/tcp

# also paste backend Ed25519 PUBKEY into /etc/lowping/bridge.toml
# (look for backend_ed25519_pubkey_hex)
nano /etc/lowping/bridge.toml

# start both
systemctl daemon-reload
systemctl enable --now grbridge grbackend

# verify
systemctl status grbridge grbackend
journalctl -fu grbridge -n 20
journalctl -fu grbackend -n 20
```

## 5. Smoke test the backend

From your laptop:

```bash
curl http://<vps-ip>:8080/v1/health     # → "ok"
curl http://<vps-ip>:8080/v1/info       # → JSON with backend pubkey
curl -X POST http://<vps-ip>:8080/v1/signup
# → JSON: { "user_id": 1, "license_token": "...", "expires_at_unix": ... }
```

Save that license_token — your client uses it.

## 6. Smoke test the bridge end-to-end

On your **Windows machine**, in the lowping repo:

```powershell
# Build the client
cargo build --release -p gr-client

# Create C:\Users\Elijah\Desktop\lowping\client.toml:
[[rules]]
listen = "127.0.0.1:9000"
bridge = "<vps-ip>:51820"
bridge_x25519_pubkey_hex = "<x25519 pubkey from earlier>"
license_token = "<token from /v1/signup>"
dest_ip = "1.1.1.1"
dest_port = 80
protocol = "tcp"

# Run client
.\target\release\grclient.exe

# In another terminal:
curl --resolve one.one.one.one:80:127.0.0.1:9000 -v http://one.one.one.one/
```

If `curl` returns a Cloudflare 301 / response, it worked: your HTTP went
Windows → grclient → tunnel → VPS bridge → Cloudflare. The `X-Forwarded-For`
or whatever the upstream sees should be your **VPS IP**, not your home IP.

## 7. Production hardening (do later, before going public)

- Put backend behind Cloudflare for free DDoS + TLS
- Add real signup flow (email verification, OAuth, Stripe)
- Move license `token_ttl_secs` from 7 days down to 24 hours and add a refresh endpoint
- Set up Prometheus + Grafana (`metrics_listen` already supported)
- Add a second bridge in NAE (NJ) and NAW (Seattle) to round out NA coverage
- Add automatic bridge healthchecks to the backend so dead bridges stop being advertised

## Troubleshooting

**"can't connect" from client**

- Vultr firewall: settings → firewall → make sure UDP 51820 is open
- ufw: `ufw status verbose` should show `51820/udp ALLOW`
- bridge running: `systemctl status grbridge`

**License verify fails**

- backend Ed25519 pubkey in `bridge.toml` must match the backend's actual key
- Re-run `grbackend gen-key` and use the printed pubkey
- Token expired: signup again

**Slow build on the VPS**

- 1 GB RAM is tight for cargo. If it OOMs:
  `sudo dd if=/dev/zero of=/swap bs=1M count=2048 && mkswap /swap && swapon /swap`
  (gives you 2GB of swap; safe to remove after build)
