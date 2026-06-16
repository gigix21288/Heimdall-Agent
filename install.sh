#!/usr/bin/env bash
#
# Heimdall Agent installer for Linux / Raspberry Pi OS / Debian / Ubuntu.
# Installs the agent to /opt/heimdall-agent and runs it as a systemd service
# that auto-starts on boot.
#
#   sudo ./install.sh                  # pcap mode (default), no auth
#   sudo ./install.sh dns              # DNS-only mode
#   sudo ./install.sh pcap MYTOKEN     # pcap + shared-token auth
#
set -euo pipefail

MODE="${1:-pcap}"
TOKEN="${2:-}"
AGENT_DIR="/opt/heimdall-agent"

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo: sudo ./install.sh ${MODE}" >&2
  exit 1
fi

echo "==> Installing dependencies (python3, scapy, websockets)"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  # Debian/Ubuntu/Raspberry Pi OS ship scapy + websockets as system packages,
  # which avoids the PEP-668 'externally-managed-environment' pip issue.
  apt-get install -y python3 python3-scapy python3-websockets \
    || pip3 install --break-system-packages scapy "websockets>=12"
else
  echo "apt-get not found — install python3, scapy and websockets manually." >&2
fi

echo "==> Installing agent to ${AGENT_DIR}"
mkdir -p "${AGENT_DIR}"
cp "$(dirname "$0")/heimdall_agent.py" "${AGENT_DIR}/"

echo "==> Creating systemd service (mode=${MODE})"
cat >/etc/systemd/system/heimdall-agent.service <<EOF
[Unit]
Description=Heimdall Agent (local LAN sensor for the Heimdall app)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 ${AGENT_DIR}/heimdall_agent.py --mode ${MODE}${TOKEN:+ --token ${TOKEN}}
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now heimdall-agent

IP_ADDR="$(hostname -I | awk '{print $1}')"
echo ""
echo "✅ Heimdall Agent is running (systemd: heimdall-agent)."
echo "   Status:  sudo systemctl status heimdall-agent"
echo "   Logs:    sudo journalctl -u heimdall-agent -f"
echo ""
echo "👉 In the app → Sentry Monitor, set the agent URL to:"
echo "   ws://${IP_ADDR}:8765/stream/packets"
if [[ -n "${TOKEN}" ]]; then
  echo "🔒 Token auth is ON — set the SAME token in the app (Settings → Agent token)."
fi
