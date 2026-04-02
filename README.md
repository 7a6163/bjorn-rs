# Bjorn (Rust Edition)

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Alpha-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust rewrite of Bjorn — an autonomous network scanning, vulnerability assessment, and offensive security tool designed for Raspberry Pi + 2.13" e-Paper HAT.

> **Rewrite of [infinition/Bjorn](https://github.com/infinition/Bjorn) (Python) in Rust for better performance on constrained hardware.**

## Why Rust?

| | Python Version | Rust Version |
|---|---|---|
| Deploy Size | ~100MB (runtime + deps) | **~9MB** (single binary) |
| Startup Time | ~10-15 seconds | **< 3 seconds** |
| Memory | ~100MB+ (pandas, etc.) | **< 50MB** |
| Concurrency Model | threading + GIL | tokio async |
| Database | CSV (no concurrency protection) | SQLite WAL (ACID) |
| Deployment | pip install + many dependencies | scp a single file |
| Actions | 12 | **27** (+PostgreSQL, MongoDB, Redis, SNMP, VNC, MQTT, HTTP) |

## Features

- **Network Scanning** — nmap host discovery + async TCP port scan
- **Vulnerability Assessment** — nmap + vulners.nse script
- **Brute Force** — 14 protocol connectors (see [Attack Modules](#attack-modules))
- **Data Exfiltration** — 13 data theft modules triggered after successful brute force
- **LLM Integration** — Ollama / Anthropic / OpenAI cascade with agentic tool-calling
- **Sentinel Watchdog** — detects new devices, ARP spoofing, port changes (zero extra traffic)
- **e-Paper Display** — Waveshare 2.13" V4, real-time Tamagotchi-style UI
- **Web Interface** — port 8000, config management, live monitoring, loot viewer
- **Headless Mode** — runs without e-Paper (outputs PNG for Web UI only)

## Attack Modules

### Brute Force (14 modules)

| Module | Port | Protocol | Implementation |
|--------|------|----------|----------------|
| SSHBruteforce | 22 | SSH | russh (pure Rust) |
| FTPBruteforce | 21 | FTP | suppaftp (pure Rust) |
| TelnetBruteforce | 23 | Telnet | raw TCP (pure Rust) |
| SQLBruteforce | 3306 | MySQL | mysql CLI |
| PostgresBruteforce | 5432 | PostgreSQL | psql CLI |
| MongoBruteforce | 27017 | MongoDB | mongosh CLI |
| RedisBruteforce | 6379 | Redis | raw TCP RESP (pure Rust) |
| SMBBruteforce | 445 | SMB | smbclient CLI |
| RDPBruteforce | 3389 | RDP | xfreerdp CLI |
| SNMPBruteforce | 161 | SNMP v2c | raw UDP (pure Rust) |
| VNCBruteforce | 5900 | VNC/RFB | raw TCP + DES (pure Rust) |
| MQTTBruteforce | 1883 | MQTT | raw TCP (pure Rust) |
| HTTPBruteforce | 80 | HTTP Basic | raw TCP (pure Rust) |
| HTTPBruteforce8080 | 8080 | HTTP Basic | raw TCP (pure Rust) |

All modules use the generic `BruteForceAction<C: Connector>` framework — each connector only implements a single `try_connect()` method.

### Data Exfiltration (13 modules)

| Module | Trigger | Method |
|--------|---------|--------|
| StealFilesSSH | SSHBruteforce | sshpass + scp |
| StealFilesFTP | FTPBruteforce | wget recursive |
| StealFilesTelnet | TelnetBruteforce | remote find via shell |
| StealDataSQL | SQLBruteforce | mysql CLI table dump |
| StealDataPostgres | PostgresBruteforce | psql COPY to CSV |
| StealDataMongo | MongoBruteforce | mongodump |
| StealDataRedis | RedisBruteforce | redis-cli --rdb / KEYS dump |
| StealFilesSMB | SMBBruteforce | smbget |
| StealFilesRDP | RDPBruteforce | xfreerdp drive mapping |
| StealDataSNMP | SNMPBruteforce | snmpwalk (system, interfaces, ARP, routes) |
| StealDataMQTT | MQTTBruteforce | mosquitto_sub (subscribe to all topics) |
| StealDataHTTP | HTTPBruteforce | scrape authenticated admin pages |
| StealDataHTTP8080 | HTTPBruteforce8080 | scrape authenticated admin pages |

Exfiltration modules are child actions — they only run after their parent brute-force module succeeds.

## Supported Hardware

| Board | Architecture | Release Binary |
|-------|-------------|----------------|
| Pi Zero W2 | AArch64 (64-bit) | `bjorn-aarch64` |
| Pi 3/4/5 | AArch64 (64-bit) | `bjorn-aarch64` |
| Pi Zero W | ARMv6 (32-bit) | `bjorn-armv6` |

## Quick Start

### Prerequisites

- Raspberry Pi with Raspberry Pi OS (Bookworm)
- Username and hostname set to `bjorn`
- 2.13" Waveshare e-Paper HAT (V4) connected to GPIO
- WiFi configured

### Install on Pi

```bash
# Download binary from release (or build from source, see below)
scp bjorn-aarch64 bjorn@<PI_IP>:/home/bjorn/bjorn
scp -r deploy/ bjorn@<PI_IP>:/home/bjorn/deploy/

# SSH into the Pi
ssh bjorn@<PI_IP>
chmod +x /home/bjorn/bjorn
sudo /home/bjorn/deploy/install.sh

# Start
sudo systemctl start bjorn.service
```

### Manual Run

```bash
sudo BJORN_ROOT=/home/bjorn/Bjorn RUST_LOG=bjorn=debug /home/bjorn/bjorn
```

### Service Control

```bash
sudo systemctl start bjorn.service     # Start
sudo systemctl stop bjorn.service      # Stop
sudo systemctl status bjorn.service    # Status
sudo journalctl -u bjorn.service -f    # Live logs
```

### Web UI

Open `http://<PI_IP>:8000` in your browser.

## Build from Source

### Host Build (for development)

```bash
cargo build --release
cargo test
```

### Cross-Compile for Pi (via Docker)

```bash
# Pi Zero W2 / Pi 3/4/5 (AArch64)
docker build --platform linux/amd64 -f Dockerfile.build -t bjorn-build .
docker create --name tmp bjorn-build sh
docker cp tmp:/bjorn dist/bjorn-aarch64
docker rm tmp
```

Or with `cross` (requires `rustup`-installed Rust):

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
```

## Architecture

```
src/
├── main.rs                     # tokio runtime, 3 async tasks, graceful shutdown
├── config/                     # BjornConfig (serde) + PathConfig
├── state/                      # AppState (ArcSwap + RwLock) + SQLite KB
├── actions/
│   ├── scanning.rs             # nmap -sn + async TCP port scan
│   ├── vuln_scanner.rs         # nmap --script vulners.nse
│   ├── brute_force/            # Generic framework + 14 protocol connectors
│   │   └── mod.rs              # BruteForceAction<C: Connector>
│   └── exfiltrate/             # 13 data theft modules (child actions)
├── orchestrator/               # Main loop, action scheduling, retry logic
├── llm/
│   ├── bridge.rs               # LLM backend cascade (Ollama → API → fallback)
│   ├── orchestrator.rs         # LLM decision modes (none/advisor/autonomous)
│   └── tools.rs                # 7 LLM tools (get_hosts, run_action, etc.)
├── sentinel/                   # Network watchdog (new devices, ARP spoof, port changes)
├── display/
│   ├── epd_v4.rs               # Waveshare 2.13" V4 SPI driver (rppal)
│   └── renderer.rs             # UI rendering (imageproc + ab_glyph)
└── web/
    ├── server.rs               # Axum (port 8000, gzip, static files)
    └── handlers.rs             # 30+ API endpoints
```

### How It Works

1. **Startup** — Loads config, opens SQLite KB, starts 3 async tasks
2. **Network Scan** — `nmap -sn` discovers hosts -> async TCP port scan -> writes to KB
3. **Orchestrator Loop** — Iterates over alive hosts -> port matching -> parent dependency check -> retry delay -> executes action
4. **Brute Force** — Loads wordlist -> concurrently tries all credential combinations -> writes successful credentials to table
5. **Exfiltration** — Connects using cracked credentials -> searches/downloads target files
6. **Display** — Renders UI every second -> sends to e-Paper via SPI -> also saves PNG for Web UI
7. **Web Server** — Axum provides live monitoring, config management, loot viewing

### Knowledge Base (SQLite)

Replaces the Python version's CSV files, providing ACID transactions and concurrency safety:

| Table | Purpose |
|-------|---------|
| `hosts` | Discovered hosts (MAC, IP, hostname, ports, alive) |
| `action_results` | Result of each action execution (success/failure + timestamp) |
| `credentials` | Cracked credentials (auto-deduplicated) |
| `vulnerabilities` | Discovered vulnerabilities (CVE, severity) |

## Configuration

Config file is located at `$BJORN_ROOT/config/shared_config.json` and can also be modified via the Web UI.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `manual_mode` | `false` | Manual mode (pauses automatic scanning) |
| `scan_interval` | `180` | Scan interval (seconds) |
| `scan_vuln_running` | `false` | Whether vulnerability scanning is enabled |
| `retry_failed_actions` | `true` | Whether to retry failed actions |
| `failed_retry_delay` | `600` | Failed retry delay (seconds) |
| `portlist` | 44 ports | List of ports to scan |
| `epd_type` | `epd2in13_V4` | e-Paper display model |

## System Dependencies

The install script (`deploy/install.sh`) installs these automatically, or install manually:

```bash
sudo apt-get install -y nmap smbclient sshpass wget zip \
    redis-tools mysql-client postgresql-client xfreerdp2-x11 \
    snmp mosquitto-clients network-manager
```

## Disclaimer

This project is strictly for **educational purposes** and **authorized security testing**. Unauthorized use for malicious activities is prohibited and may be prosecuted by law. The authors disclaim any responsibility for misuse.

## License

MIT License. See [LICENSE](LICENSE) for details.

Based on [infinition/Bjorn](https://github.com/infinition/Bjorn) (Python).
