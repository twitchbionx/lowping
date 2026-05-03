#!/usr/bin/env bash
# install-bridge.sh — bootstrap a fresh Ubuntu 24.04 VPS as a lowping bridge.
#
# Usage (as root or via sudo):
#   curl -L https://raw.githubusercontent.com/twitchbionx/lowping/main/deploy/install-bridge.sh | bash
#   # or:
#   wget https://raw.githubusercontent.com/twitchbionx/lowping/main/deploy/install-bridge.sh
#   chmod +x install-bridge.sh
#   ./install-bridge.sh
#
# After completion, edit /etc/lowping/bridge.toml then:
#   systemctl enable --now grbridge
#   journalctl -fu grbridge

set -euo pipefail

REPO_URL="https://github.com/twitchbionx/lowping.git"
INSTALL_PREFIX="/usr/local/bin"
CONFIG_DIR="/etc/lowping"
SERVICE_USER="grbridge"
LOG_DIR="/var/log/lowping"
LISTEN_PORT="${LISTEN_PORT:-51820}"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (try: sudo $0)"
    exit 1
fi

echo "==> updating apt and installing build prerequisites"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    build-essential pkg-config libssl-dev curl git ufw

if ! command -v cargo >/dev/null; then
    echo "==> installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

echo "==> creating service user and dirs"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
chmod 750 "$CONFIG_DIR" "$LOG_DIR"

echo "==> cloning lowping"
WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT
git clone --depth 1 "$REPO_URL" "$WORKDIR/lowping"
cd "$WORKDIR/lowping"

echo "==> building grbridge (this takes a few minutes)"
cargo build --release -p gr-bridge

echo "==> installing binary to $INSTALL_PREFIX"
install -m 0755 target/release/grbridge "$INSTALL_PREFIX/grbridge"

echo "==> installing systemd unit"
install -m 0644 deploy/systemd/grbridge.service /etc/systemd/system/grbridge.service
systemctl daemon-reload

echo "==> writing config skeleton (you must edit this!)"
if [[ ! -f "$CONFIG_DIR/bridge.toml" ]]; then
    install -m 0640 -o "$SERVICE_USER" -g "$SERVICE_USER" \
        deploy/bridge.toml.example "$CONFIG_DIR/bridge.toml"
    echo
    echo "==> generating fresh X25519 keypair for this bridge"
    KEY_OUTPUT=$("$INSTALL_PREFIX/grbridge" gen-key)
    echo "$KEY_OUTPUT"
    SECKEY=$(echo "$KEY_OUTPUT" | grep bridge_x25519_seckey_hex | sed -E 's/.*"([0-9a-f]+)".*/\1/')
    if [[ -n "$SECKEY" ]]; then
        sed -i "s|REPLACE_WITH_YOUR_32_BYTES_HEX|$SECKEY|" "$CONFIG_DIR/bridge.toml"
        echo "==> wrote secret key to $CONFIG_DIR/bridge.toml"
    fi
fi

echo "==> opening UDP port $LISTEN_PORT in ufw"
ufw allow "$LISTEN_PORT/udp" >/dev/null
ufw allow OpenSSH >/dev/null
ufw --force enable >/dev/null

echo
echo "================================================================"
echo "lowping bridge installation complete."
echo
echo "next steps:"
echo "  1. Edit $CONFIG_DIR/bridge.toml and set:"
echo "     - backend_ed25519_pubkey_hex (from your grbackend gen-key)"
echo "  2. Add this bridge's X25519 pubkey to your backend's bridge directory"
echo "  3. Start the service:"
echo "     systemctl enable --now grbridge"
echo "     journalctl -fu grbridge"
echo
echo "Bridge will listen on UDP $LISTEN_PORT (open in firewall)."
echo "================================================================"
