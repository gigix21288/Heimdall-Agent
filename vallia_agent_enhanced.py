#!/usr/bin/env python3
"""
Vallia Agent Enhanced — Analisi sicurezza completa per rete locale.

Features portate dall'app Vallia:
- Network scan (TCP sweep + ARP)
- Router audit (Telnet, FTP, UPnP, HTTP admin)
- Tracker detection (IP → org → tracker match)
- Device creepiness rating (microfono, camera, cloud, EOL)
- Privacy label per dispositivo
- REST API per SecureCheck

Uso: python vallia_agent_enhanced.py [--port 8766] [--token TOKEN]
"""

import json
import os
import re
import socket
import struct
import subprocess
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ─── CONFIGURAZIONE ─────────────────────────────────────────────────────────
DEFAULT_PORT = 8766
TOKEN = os.environ.get("VALLIA_TOKEN", None)
DATA_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── CARICA DATI ────────────────────────────────────────────────────────────
def load_json(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

TRACKERS = load_json("trackers.json")
IP_ORGS = load_json("ip_orgs.json")
DEVICE_PRIVACY = load_json("device_privacy.json")

agent_state = {
    "started_at": time.time(),
    "version": "2.0.0-enhanced",
    "devices_seen": 0,
    "packets_captured": 0,
    "last_scan": None,
    "discovered_devices": [],
    "router_audit": None,
    "tracker_results": [],
    "scanning": False,
    "mode": "pcap",
    "interface": None,
    "gateway_ip": None,
}

# ─── NETWORK UTILS ──────────────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_gateway_ip() -> str:
    """Ottiene l'IP del gateway di default."""
    try:
        if os.name == "nt":
            output = subprocess.check_output("ipconfig", text=True, timeout=5)
            for line in output.splitlines():
                if "Default Gateway" in line and "." in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        gw = parts[-1].strip()
                        if gw and gw[0].isdigit():
                            return gw
        else:
            output = subprocess.check_output("ip route | grep default", shell=True, text=True, timeout=5)
            m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", output)
            if m:
                return m.group(1)
    except Exception:
        pass
    # Fallback: primo IP della sottorete con .1
    ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"

def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def cidr_matches(ip: str, cidr: str) -> bool:
    """Verifica se un IP appartiene a un blocco CIDR."""
    if "/" not in cidr:
        return False
    network, bits = cidr.split("/")
    bits = int(bits)
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (ip_to_int(ip) & mask) == (ip_to_int(network) & mask)

# ─── NETWORK SCAN ───────────────────────────────────────────────────────────

def scan_network(subnet: str = None, timeout: float = 1.0) -> list:
    """Scansione TCP sweep della sottorete locale."""
    if subnet is None:
        ip = get_local_ip()
        parts = ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    base = subnet.split("/")[0]
    parts = base.split(".")
    prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

    devices = []
    common_ports = [80, 443, 22, 21, 23, 8080, 8443, 554, 5000, 2869]

    for i in range(1, 255):
        ip = f"{prefix}{i}"
        open_ports = []
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass

        if open_ports:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            devices.append({"ip": ip, "hostname": hostname, "open_ports": open_ports, "mac": None})

    # ARP table per MAC
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True, timeout=3)
        for line in arp_output.splitlines():
            for dev in devices:
                if dev["ip"] in line:
                    m = re.search(r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
                    if m:
                        dev["mac"] = m.group(1).replace("-", ":").lower()
    except Exception:
        pass

    return devices

# ─── ROUTER AUDIT ───────────────────────────────────────────────────────────

def audit_router(gateway_ip: str = None, timeout: float = 1.5) -> dict:
    """Audit del router/gateway: verifica porte e servizi pericolosi."""
    if gateway_ip is None:
        gateway_ip = get_gateway_ip()

    checks = {
        "telnet": {"port": 23, "risk": "high", "label": "Telnet esposto", "fix": "Disabilita Telnet. Usa solo SSH."},
        "ftp": {"port": 21, "risk": "medium", "label": "FTP esposto", "fix": "Usa SFTP o SCP invece di FTP."},
        "upnp_ssdp": {"service": "upnp", "risk": "medium", "label": "UPnP potenzialmente attivo", "fix": "Disabilita UPnP sul router se non necessario."},
        "smb": {"port": 445, "risk": "high", "label": "SMB esposto", "fix": "Disabilita SMBv1 e limita accesso a SMB."},
        "http_admin": {"port": 80, "risk": "low", "label": "Interfaccia admin HTTP", "fix": "Usa HTTPS per l'amministrazione."},
        "https_admin": {"port": 443, "risk": "low", "label": "Interfaccia admin HTTPS", "fix": "Verifica che usi credenziali robuste."},
        "alt_http": {"port": 8080, "risk": "medium", "label": "Admin su porta alternativa", "fix": "Verifica se e necessaria."},
    }

    results = []
    for key, check in checks.items():
        if "port" in check:
            port = check["port"]
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((gateway_ip, port))
                s.close()
                found = result == 0
            except Exception:
                found = False

            if "service" in check and check["service"] == "upnp":
                # UPnP: prova a connetterti alla porta 2869 o 5000
                found = False
                for upnp_port in [2869, 5000, 1900]:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(timeout)
                        if s.connect_ex((gateway_ip, upnp_port)) == 0:
                            found = True
                            break
                        s.close()
                    except Exception:
                        pass

            results.append({
                "check": key,
                "label": check["label"],
                "port": check.get("port"),
                "found": found,
                "risk": check["risk"],
                "fix": check["fix"],
            })

    score = 100
    for r in results:
        if r["found"]:
            if r["risk"] == "high":
                score -= 20
            elif r["risk"] == "medium":
                score -= 10
            elif r["risk"] == "low":
                score -= 5

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    return {
        "gateway_ip": gateway_ip,
        "checks": results,
        "issues_found": [r for r in results if r["found"]],
        "score": max(0, score),
        "grade": grade,
    }

# ─── TRACKER DETECTION ──────────────────────────────────────────────────────

def detect_trackers(destinations: list) -> list:
    """
    Rileva comunicazioni verso tracker noti.
    destinations: lista di {"ip": "1.2.3.4"} o {"ip": "1.2.3.4", "org": "Google"}
    """
    results = []
    for dest in destinations:
        ip = dest.get("ip", "")
        org = dest.get("org", "")

        # Se non abbiamo l'org, cerchiamolo negli ip_orgs
        if not org:
            for entry in IP_ORGS:
                if cidr_matches(ip, entry["cidr"]):
                    org = entry["org"]
                    break

        if not org:
            continue

        # Cerca match nei tracker
        org_lower = org.lower()
        for tracker in TRACKERS:
            for kw in tracker["keywords"]:
                if kw in org_lower:
                    results.append({
                        "ip": ip,
                        "org": org,
                        "tracker_name": tracker["name"],
                        "category": tracker["category"],
                    })
                    break  # Un solo match per tracker

    return results

# ─── DEVICE CREEPINESS ─────────────────────────────────────────────────────

def rate_device_creepiness(device: dict) -> dict:
    """
    Valuta quanto un dispositivo e invasivo per la privacy.
    Restituisce score 0-100 (piu alto = piu invasivo).
    """
    hostname = (device.get("hostname") or "").lower()
    mac = (device.get("mac") or "").lower()
    ports = device.get("open_ports", [])
    ip = device.get("ip", "")

    score = 0
    traits = []
    eol = False
    manufacturer = "Sconosciuto"

    # Cerca match nel database device_privacy
    for entry in DEVICE_PRIVACY:
        keywords = entry.get("keywords", [])
        for kw in keywords:
            if kw.lower() in hostname or kw.lower() in mac:
                for t in entry.get("traits", []):
                    if t not in traits:
                        traits.append(t)
                if entry.get("eol"):
                    eol = True
                manufacturer = entry["keywords"][0]
                break

    # Euristiche basate sulle porte
    is_gateway = ip.endswith(".1") or ip.endswith(".254")
    if is_gateway:
        manufacturer = "Router/Gateway"
        # I router non sono di per se invasivi, ma verranno auditati separatamente

    if 554 in ports:
        if "camera" not in traits:
            traits.append("camera")
        if "RTSP stream" not in traits:
            traits.append("RTSP stream")

    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        if "webserver" not in traits:
            traits.append("webserver")

    if 22 in ports:
        if "SSH" not in traits:
            traits.append("SSH")

    if 21 in ports or 23 in ports:
        if "legacy_protocol" not in traits:
            traits.append("legacy_protocol")

    # Calcolo score invasivita
    trait_weights = {
        "microphone": 20,
        "camera": 25,
        "alwaysListening": 30,
        "cloudDependent": 15,
        "locationAware": 15,
        "RTSP stream": 15,
        "webserver": 2,
        "SSH": 2,
        "legacy_protocol": 5,
    }
    for t in traits:
        score += trait_weights.get(t, 5)

    # Penalita EOL
    if eol:
        score += 25

    level = "low" if score < 20 else "medium" if score < 50 else "high" if score < 75 else "critical"

    return {
        "score": min(100, score),
        "level": level,
        "traits": traits,
        "eol": eol,
        "manufacturer": manufacturer,
    }

# ─── PRIVACY LABEL ──────────────────────────────────────────────────────────

def build_privacy_label(device: dict, creepiness: dict) -> dict:
    """
    Costruisce un'etichetta privacy in stile 'nutrition label' per dispositivo.
    """
    hostname = device.get("hostname") or device.get("ip")
    ports = device.get("open_ports", [])

    phones_home = len(ports) > 0
    grade = "A" if creepiness["score"] < 20 else "B" if creepiness["score"] < 40 else "C" if creepiness["score"] < 60 else "D" if creepiness["score"] < 80 else "F"

    return {
        "device": hostname,
        "ip": device.get("ip"),
        "manufacturer": creepiness["manufacturer"],
        "grade": grade,
        "creepiness_score": creepiness["score"],
        "phones_home": phones_home,
        "traits": creepiness["traits"],
        "eol": creepiness["eol"],
        "open_ports": ports,
    }

# ─── ANALISI COMPLETA ───────────────────────────────────────────────────────

def full_analysis(subnet: str = None, timeout: float = 1.0) -> dict:
    """Esegue scansione completa: network + router + tracker + creepiness + privacy."""
    devices = scan_network(subnet, timeout)
    gateway_ip = get_gateway_ip()
    router = audit_router(gateway_ip, timeout)

    # Arricchisci ogni dispositivo
    enriched = []
    destinations_for_tracker = []
    for d in devices:
        creepiness = rate_device_creepiness(d)
        privacy_label = build_privacy_label(d, creepiness)

        # Risk flags
        risk_flags = []
        if creepiness["level"] in ("high", "critical"):
            risk_flags.append(f"Dispositivo {creepiness['level']} ({creepiness['score']}/100)")
        if creepiness["eol"]:
            risk_flags.append("Dispositivo End-of-Life")
        risky_ports = [p for p in d.get("open_ports", []) if p in (21, 22, 23, 25, 3389, 3306, 5432, 6379)]
        if risky_ports:
            risk_flags.append(f"Porte rischiose: {risky_ports}")

        risk_level = "high" if len(risk_flags) >= 3 else "medium" if len(risk_flags) >= 1 else "low"

        enriched.append({
            **d,
            "creepiness": creepiness,
            "privacy_label": privacy_label,
            "risk_flags": risk_flags,
            "risk_level": risk_level,
        })

        # Prepara per tracker detection (se il dispositivo comunica con IP esterni)
        destinations_for_tracker.append({"ip": d["ip"], "org": creepiness.get("manufacturer", "")})

    # Tracker detection
    trackers = detect_trackers(destinations_for_tracker)

    # Score rete interna
    total_devices = len(enriched)
    risky = sum(1 for d in enriched if d["risk_level"] == "high")
    medium = sum(1 for d in enriched if d["risk_level"] == "medium")
    internal_score = max(0, min(100, 100 - (risky * 15) - (medium * 5))) if total_devices > 0 else 100

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subnet": subnet or "auto",
        "gateway_ip": gateway_ip,
        "router_audit": router,
        "devices": enriched,
        "device_count": total_devices,
        "risky_devices": risky,
        "medium_devices": medium,
        "internal_score": internal_score,
        "trackers_found": trackers,
        "tracker_count": len(trackers),
    }

# ─── HTTP HANDLER ───────────────────────────────────────────────────────────

class ValliaHandler(BaseHTTPRequestHandler):

    def _check_auth(self) -> bool:
        if TOKEN is None:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {TOKEN}"

    def _send(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def _error(self, msg, status=400):
        self._send({"error": msg}, status)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        if not self._check_auth():
            return self._error("Non autorizzato", 401)

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/health":
            self._send({
                "status": "online",
                "version": agent_state["version"],
                "uptime_seconds": round(time.time() - agent_state["started_at"]),
                "last_scan": agent_state["last_scan"],
                "local_ip": get_local_ip(),
                "gateway_ip": get_gateway_ip(),
                "mode": agent_state["mode"],
            })

        elif path == "/api/devices":
            self._send({
                "devices": agent_state["discovered_devices"],
                "count": len(agent_state["discovered_devices"]),
                "last_scan": agent_state["last_scan"],
            })

        elif path == "/api/router":
            if agent_state["router_audit"]:
                self._send(agent_state["router_audit"])
            else:
                self._error("Nessun audit router disponibile. Esegui /api/scan prima.", 404)

        elif path == "/api/trackers":
            self._send({
                "trackers": agent_state["tracker_results"],
                "count": len(agent_state["tracker_results"]),
            })

        elif path == "/api/config":
            self._send({
                "mode": agent_state["mode"],
                "interface": agent_state["interface"],
                "token_required": TOKEN is not None,
                "local_ip": get_local_ip(),
                "gateway_ip": get_gateway_ip(),
            })

        else:
            self._error("Endpoint non trovato", 404)

    def do_POST(self):
        if not self._check_auth():
            return self._error("Non autorizzato", 401)

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if path == "/api/scan":
            if agent_state["scanning"]:
                return self._error("Scansione gia in corso", 409)

            agent_state["scanning"] = True
            try:
                subnet = body.get("subnet")
                timeout = body.get("timeout", 1.0)
                result = full_analysis(subnet, timeout)

                agent_state["discovered_devices"] = result["devices"]
                agent_state["router_audit"] = result["router_audit"]
                agent_state["tracker_results"] = result["trackers_found"]
                agent_state["last_scan"] = result["timestamp"]
                agent_state["devices_seen"] = result["device_count"]

                self._send(result, 201)
            except Exception as e:
                self._error(str(e), 500)
            finally:
                agent_state["scanning"] = False

        elif path == "/api/router/audit":
            try:
                gw = body.get("gateway_ip") or get_gateway_ip()
                result = audit_router(gw)
                agent_state["router_audit"] = result
                self._send(result)
            except Exception as e:
                self._error(str(e), 500)

        elif path == "/api/config":
            if "mode" in body and body["mode"] in ("pcap", "dns"):
                agent_state["mode"] = body["mode"]
            if "interface" in body:
                agent_state["interface"] = body["interface"]
            self._send({"success": True, "config": {
                "mode": agent_state["mode"],
                "interface": agent_state["interface"],
            }})

        else:
            self._error("Endpoint non trovato", 404)

    def log_message(self, fmt, *args):
        if args[1] != "200":
            print(f"[Agent] {args[0]} {args[1]} {args[2]}")

# ─── MAIN ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Vallia Agent Enhanced — Analisi sicurezza rete locale")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", type=str, default=TOKEN)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    if args.token:
        TOKEN = args.token

    ip = get_local_ip()
    gw = get_gateway_ip()
    print(f"✅ Vallia Agent Enhanced v{agent_state['version']}")
    print(f"   IP locale: {ip}  |  Gateway: {gw}")
    print(f"   Porta REST: {args.port}")
    print(f"   Endpoint:")
    print(f"   GET  /api/health        — Stato")
    print(f"   POST /api/scan          — Scansione completa")
    print(f"   GET  /api/devices       — Dispositivi")
    print(f"   POST /api/router/audit  — Audit router")
    print(f"   GET  /api/trackers      — Tracker rilevati")
    if TOKEN:
        print(f"   ⚠️  Auth token: Bearer <token>")

    server = HTTPServer((args.host, args.port), ValliaHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Arresto.")
        server.shutdown()
