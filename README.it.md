# Heimdall Agent

🇮🇹 Italiano · [🇬🇧 English](README.md)

Una piccola **sonda di rete locale** per l'app [Heimdall OS](https://github.com/).
Osserva il traffico della tua rete e trasmette le **intestazioni dei pacchetti**
all'app via WebSocket **sulla tua LAN**.

> **100% privato.** L'agente serve i dati **solo** ai tuoi dispositivi sulla tua
> rete privata. Niente viene inviato ad alcun cloud, a noi, o fuori dalla tua LAN.
> Nessun account, nessuna telemetria.

Sblocca tre funzioni dell'app che richiedono dati di traffico reali:
**Sentry Monitor**, la **mappa del traffico** (data-flow) e la **valutazione del
rischio per-dispositivo in tempo reale**. (Tutto il resto dell'app — scansione,
punteggio, test Wi-Fi, Vault, guardiano change-detection, Copilot — funziona
**senza** l'agente.)

---

## ⚠️ Leggi prima: dove può girare l'agente?

Su una normale rete commutata/Wi-Fi, ogni dispositivo vede **solo il proprio**
traffico. Per vedere il traffico **degli altri**, l'agente deve girare in un
**punto di passaggio obbligato**:

```
Internet ── [ MODEM / ROUTER ] ── switch / Wi-Fi ── tutti i tuoi dispositivi
                    ▲
        l'agente deve stare qui (o sul router stesso)
```

Posizioni adatte:
- Un **router OpenWrt / pfSense** (dove passa tutto il traffico).
- Un **Raspberry Pi** "in linea" (tra il modem e il resto della rete).
- Una macchina che riceve traffico **mirror/SPAN** da uno switch gestito.

**Non** funziona in modo utile su un normale portatile collegato in Wi-Fi (vedrebbe
solo il traffico di quel portatile).

---

## Modalità

| Modalità         | Cosa cattura                                          | Quando usarla…                          |
|------------------|-------------------------------------------------------|-----------------------------------------|
| `pcap` (default) | Intestazioni complete: IP src/dst, porte, **byte**, proto | Vuoi la mappa del traffico più ricca |
| `dns`            | Solo le risoluzioni DNS: dispositivo → dominio → IP   | Vuoi **meno dati / più privacy**        |

```bash
sudo python3 heimdall_agent.py            # pcap (default)
sudo python3 heimdall_agent.py --mode dns # solo DNS
```

---

## Installazione — scegli la forma adatta a te

### 1) Script veloce (qualsiasi Linux / Raspberry Pi) — la più facile
```bash
git clone https://github.com/gigix21288/Heimdall-Agent.git
cd Heimdall-Agent
sudo ./install.sh          # oppure: sudo ./install.sh dns
```
Installa le dipendenze, copia l'agente in `/opt/heimdall-agent` e lo avvia come
**servizio systemd** che parte all'accensione. Stampa l'URL esatto da incollare
nell'app.

### 2) Docker (NAS / homelab)
```bash
git clone https://github.com/gigix21288/Heimdall-Agent.git
cd Heimdall-Agent
docker compose up -d --build
```
Usa la rete host + i permessi di cattura raw per vedere la LAN. Modifica
`command:` in `docker-compose.yml` per passare a `--mode dns`.

### 3) Raspberry Pi (guidata)
1. Scrivi **Raspberry Pi OS Lite** su una microSD e avvia il Pi (abilita SSH).
2. Posiziona il Pi così che veda il traffico (in linea al gateway, o come target
   di mirroring del router).
3. `sudo ./install.sh` (come la forma 1). Il Pi esegue l'agente a ogni avvio.

> Volutamente **non** distribuiamo un'immagine `.img` da diversi GB: Raspberry Pi
> OS standard + l'installer da una riga è più leggero da scaricare e molto più
> facile da tenere aggiornato.

### 4) Router OpenWrt (avanzata / sperimentale)
Vedi [`openwrt/`](openwrt/). Richiede l'OpenWrt SDK per compilare l'`.ipk` e
`scapy`/`websockets` installati via `pip` sul router (pesanti per molti
dispositivi). Per la maggior parte degli utenti consigliamo le forme 1–3.

---

## Punta l'app all'agente

Nell'app Heimdall → **Sentry Monitor**, imposta l'URL dell'agente su:

```
ws://<ip-host-agente>:8765/stream/packets
```

es. `ws://192.168.1.50:8765/stream/packets`. L'app accetta **solo** indirizzi
privati (RFC-1918) — per scelta rifiuta qualsiasi indirizzo pubblico.

---

## Verifica che funzioni
```bash
sudo systemctl status heimdall-agent     # il servizio è attivo?
sudo journalctl -u heimdall-agent -f     # log in tempo reale
```
Apri **Sentry Monitor** nell'app e connettiti: dovresti vedere il contatore
pacchetti salire e la **mappa del traffico** popolarsi.

---

## Note di sicurezza
- In questa versione l'agente ascolta sulla LAN **senza autenticazione**: si fida
  della rete locale (e l'app rifiuta indirizzi non locali). Usalo solo su una rete
  che controlli. Un'opzione con token condiviso è in roadmap.
- La cattura pacchetti richiede **root** (socket raw). Per questo il servizio
  systemd gira come root.
- La modalità `dns` è la scelta più rispettosa della privacy: vede solo **quali
  domini/IP** un dispositivo risolve, mai il contenuto o i volumi del traffico.

## Requisiti
- Python 3.9+, `scapy`, `websockets` (l'installer li gestisce su Debian/Pi OS).
- Privilegi di root; una posizione di cattura come descritto sopra.

## Licenza
MIT (o a tua scelta).
