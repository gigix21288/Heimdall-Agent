#!/usr/bin/env python3
"""
Heimdall Agent — a local LAN sensor for the Heimdall OS phone app.

It captures packet headers on your network and streams them to the Heimdall app
over a WebSocket on your LAN. It is 100% local: it only ever serves to your own
devices over the private network — nothing is ever sent to any cloud or to us.

MODES
  pcap  (default)  Full packet headers: src/dst IP, ports, byte size, protocol.
                   Richest data — powers the data-flow map with real volumes.
  dns              Only DNS lookups: which device resolved which domain → IP.
                   Far less data, more privacy; no byte volumes.

REQUIREMENTS
  * Python 3.9+, with `scapy` and `websockets` installed (see README).
  * Root/sudo (raw packet capture needs elevated privileges).
  * Must run where it can SEE the LAN traffic — a router, or a Raspberry Pi / PC
    at a network choke point. A normal Wi-Fi host only sees its own traffic.

WIRE FORMAT (one JSON object per WebSocket text frame) — matches the app exactly:
  {"src_ip":"…","dst_ip":"…","src_port":0,"dst_port":0,"size":0,"proto":"tcp","ts":0}

USAGE
  sudo python3 heimdall_agent.py                 # pcap mode, port 8765
  sudo python3 heimdall_agent.py --mode dns      # DNS-only mode
  sudo python3 heimdall_agent.py --iface eth0    # pin a capture interface

Then, in the app → Sentry Monitor, set the agent URL to:
  ws://<this-host-ip>:8765/stream/packets
"""

import argparse
import asyncio
import json
import sys
import threading
import time

try:
    import websockets
except ImportError:
    sys.exit("Missing dependency 'websockets'. Install it (see README): "
             "apt install python3-websockets  OR  pip install 'websockets>=12'")

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS
except ImportError:
    sys.exit("Missing dependency 'scapy'. Install it (see README): "
             "apt install python3-scapy  OR  pip install scapy")

DEFAULT_PORT = 8765
WS_PATH = "/stream/packets"


class Hub:
    """Fans captured frames out to every connected app client.

    The sniffer runs on a background thread and hands frames to the asyncio
    event loop via `submit()`; `broadcast_forever()` drains them to clients.
    """

    def __init__(self, loop):
        self._loop = loop
        self._clients = set()
        self._queue = asyncio.Queue(maxsize=10000)

    def register(self, ws):
        self._clients.add(ws)

    def unregister(self, ws):
        self._clients.discard(ws)

    def submit(self, frame):
        # Called from the sniffer thread → bounce onto the event loop.
        self._loop.call_soon_threadsafe(self._enqueue, frame)

    def _enqueue(self, frame):
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass  # Drop under pressure; the app only needs a recent window.

    async def broadcast_forever(self):
        while True:
            frame = await self._queue.get()
            if not self._clients:
                continue
            dead = []
            for ws in self._clients:
                try:
                    await ws.send(frame)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.unregister(ws)


def _frame(src_ip, dst_ip, src_port, dst_port, size, proto, ts):
    return json.dumps({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "size": int(size),
        "proto": proto,
        "ts": int(ts),
    })


def make_pcap_handler(hub):
    def handle(pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        sport = dport = 0
        proto = "other"
        if TCP in pkt:
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
        hub.submit(_frame(ip.src, ip.dst, sport, dport, len(pkt), proto,
                          time.time()))
    return handle


def make_dns_handler(hub):
    """Emit one frame per resolved A record: the device → the external IP it is
    about to talk to. Lightweight and privacy-respecting (DNS metadata only)."""
    def handle(pkt):
        if DNS not in pkt or IP not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 1:  # responses only
            return
        client_ip = pkt[IP].dst  # the device that asked
        count = int(dns.ancount or 0)
        for i in range(count):
            try:
                rr = dns.an[i]
                if getattr(rr, "type", None) != 1:  # A record only
                    continue
                resolved = rr.rdata
                if isinstance(resolved, bytes):
                    resolved = resolved.decode(errors="ignore")
                hub.submit(_frame(client_ip, str(resolved), 0, 443, len(pkt),
                                  "dns", time.time()))
            except Exception:
                break
    return handle


def start_sniffer(hub, mode, iface):
    bpf = "udp port 53" if mode == "dns" else "ip"
    prn = make_dns_handler(hub) if mode == "dns" else make_pcap_handler(hub)

    def run():
        try:
            sniff(filter=bpf, prn=prn, store=False, iface=iface)
        except PermissionError:
            print("[Heimdall Agent] ERROR: packet capture needs root. "
                  "Re-run with sudo.", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — surface any capture failure
            print(f"[Heimdall Agent] capture error: {e}", file=sys.stderr)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


async def main_async(args):
    loop = asyncio.get_running_loop()
    hub = Hub(loop)
    start_sniffer(hub, args.mode, args.iface)
    asyncio.ensure_future(hub.broadcast_forever())

    async def handler(ws):
        hub.register(ws)
        try:
            async for _ in ws:  # we don't expect inbound messages
                pass
        except Exception:
            pass
        finally:
            hub.unregister(ws)

    print(f"[Heimdall Agent] mode={args.mode}  "
          f"serving ws://0.0.0.0:{args.port}{WS_PATH}")
    print("[Heimdall Agent] In the app → Sentry Monitor, set the URL to "
          f"ws://<this-host-ip>:{args.port}{WS_PATH}")
    async with websockets.serve(handler, "0.0.0.0", args.port):
        await asyncio.Future()  # run forever


def main():
    p = argparse.ArgumentParser(
        description="Heimdall Agent — local LAN sensor for the Heimdall app.")
    p.add_argument("--mode", choices=["pcap", "dns"], default="pcap",
                   help="pcap = full packet headers (default); "
                        "dns = DNS lookups only (lighter, more private)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"WebSocket port (default {DEFAULT_PORT})")
    p.add_argument("--iface", default=None,
                   help="capture interface (default: scapy's default route)")
    args = p.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[Heimdall Agent] stopped")


if __name__ == "__main__":
    main()
