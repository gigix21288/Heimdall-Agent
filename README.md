# Heimdall Agent

🇬🇧 English · [🇮🇹 Italiano](README.it.md)

A tiny **local network sensor** for the [Heimdall OS](https://github.com/) phone app.
It watches your network's traffic and streams **packet headers** to the app over a
WebSocket **on your LAN**.

> **100% private.** The agent only ever serves data to your own devices over your
> private network. Nothing is sent to any cloud, to us, or anywhere off your LAN.
> No account, no telemetry.

It unlocks three app features that need real traffic data:
**Sentry Monitor**, the **Data-flow map**, and **live per-device risk evaluation**.
(Everything else in the app — scanning, security score, Wi-Fi test, Vault,
change-detection guardian, Copilot — works **without** the agent.)

---

## ⚠️ Read this first: where can the agent run?

On a normal switched/Wi-Fi network, each device only sees **its own** traffic.
To see **other devices'** traffic, the agent must run at a **network choke point**:

```
Internet ── [ MODEM / ROUTER ] ── switch / Wi-Fi ── all your devices
                    ▲
            the agent must sit here (or on the router itself)
```

Good homes for the agent:
- An **OpenWrt / pfSense router** (runs right where all traffic flows).
- A **Raspberry Pi** placed inline (between modem and the rest of the network).
- A box that receives **mirrored/SPAN** traffic from a managed switch.

It will **not** work usefully on a normal laptop joined over Wi-Fi (it would only
see that laptop's own traffic).

---

## Modes

| Mode            | What it captures                                   | Use when…                                   |
|-----------------|----------------------------------------------------|---------------------------------------------|
| `pcap` (default)| Full headers: src/dst IP, ports, **byte size**, proto | You want the richest data-flow map        |
| `dns`           | Only DNS lookups: device → domain → IP             | You want **less data / more privacy**       |

```bash
sudo python3 heimdall_agent.py            # pcap (default)
sudo python3 heimdall_agent.py --mode dns # DNS-only
```

---

## Install — pick the form that fits your setup

### 1) Quick script (any Linux box / Raspberry Pi) — easiest
```bash
git clone https://github.com/gigix21288/Heimdall-Agent.git
cd Heimdall-Agent
sudo ./install.sh          # or: sudo ./install.sh dns
```
This installs deps, copies the agent to `/opt/heimdall-agent`, and runs it as a
**systemd service** that starts on boot. It prints the exact URL to paste in the app.

### 2) Docker (NAS / homelab)
```bash
git clone https://github.com/gigix21288/Heimdall-Agent.git
cd Heimdall-Agent
docker compose up -d --build
```
Uses host networking + raw-capture caps so it can see the LAN. Edit the `command:`
in `docker-compose.yml` to switch to `--mode dns`.

### 3) Raspberry Pi (guided)
1. Flash **Raspberry Pi OS Lite** to an SD card and boot the Pi (enable SSH).
2. Position the Pi so it sees the traffic (inline at the gateway, or as your
   router's mirror target).
3. `sudo ./install.sh` (same as form 1). The Pi now runs the agent on every boot.

> We deliberately don't ship a multi-GB prebuilt `.img`: a standard Pi OS + the
> one-line installer is lighter to download and far easier to keep updated.

### 4) OpenWrt router (advanced / experimental)
See [`openwrt/`](openwrt/). Requires the OpenWrt SDK to build the `.ipk`, and
`scapy`/`websockets` to be `pip`-installed on the router (heavy for many devices).
For most users, forms 1–3 are recommended.

---

## Point the app at the agent

In the Heimdall app → **Sentry Monitor**, set the agent URL to:

```
ws://<agent-host-ip>:8765/stream/packets
```

e.g. `ws://192.168.1.50:8765/stream/packets`. The app **only** accepts private
(RFC-1918) addresses — it will refuse anything public, by design.

---

## Verify it's working
```bash
sudo systemctl status heimdall-agent     # service up?
sudo journalctl -u heimdall-agent -f     # live logs
```
Open **Sentry Monitor** in the app and tap connect — you should see the packet
counter rise, and the **Data-flow map** populate.

---

## Security notes
- The agent listens on your LAN with **no authentication** in this version — it
  trusts the local network (and the app refuses non-local addresses). Run it only
  on a network you control. A shared-token option is on the roadmap.
- Packet capture needs **root** (raw sockets). The systemd service runs as root
  for that reason.
- `dns` mode is the most privacy-conscious choice: it only ever sees which
  **domains/IPs** a device resolves, never the traffic contents or volumes.

## Requirements
- Python 3.9+, `scapy`, `websockets` (the installer handles these on Debian/Pi OS).
- Root privileges; a capture position as described above.

## License
MIT (or your choice).
