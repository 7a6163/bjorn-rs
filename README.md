# Bjorn (Rust Edition)

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Alpha-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust rewrite of Bjorn — an autonomous network scanning, vulnerability assessment, and offensive security tool designed for Raspberry Pi + 2.13" e-Paper HAT.

> **Rewrite of [infinition/Bjorn](https://github.com/infinition/Bjorn) (Python) in Rust for better performance on constrained hardware.**

## Why Rust?

| | Python Version | Rust Version |
|---|---|---|
| Deploy Size | ~100MB (runtime + deps) | **6.7MB** (single binary) |
| Startup Time | ~10-15 seconds | **< 3 seconds** |
| Memory | ~100MB+ (pandas, etc.) | **< 50MB** |
| Concurrency Model | threading + GIL | tokio async |
| Database | CSV (no concurrency protection) | SQLite WAL (ACID) |
| Deployment | pip install + many dependencies | scp a single file |
| Actions | 12 | **18** (+PostgreSQL, MongoDB, Redis) |

## Features

- **Network Scanning** — nmap host discovery + async TCP port scan
- **Vulnerability Assessment** — nmap + vulners.nse script
- **Brute Force** — SSH, FTP, Telnet, SMB, RDP, MySQL, PostgreSQL, MongoDB, Redis
- **Data Exfiltration** — SFTP, FTP download, SQL dump, SMB share grab, Redis dump
- **e-Paper Display** — Waveshare 2.13" V4, real-time Tamagotchi-style UI
- **Web Interface** — port 8000, config management, live monitoring, loot viewer
- **Headless Mode** — runs without e-Paper (outputs PNG for Web UI only)

## Supported Hardware

| Board | Architecture | Target |
|-------|-------------|--------|
| Pi Zero W2 | AArch64 (64-bit) | `aarch64-unknown-linux-gnu` |
| Pi Zero W | ARMv6 (32-bit) | `arm-unknown-linux-gnueabihf` |
| Pi 3/4/5 | AArch64 (64-bit) | `aarch64-unknown-linux-gnu` |

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
│   ├── brute_force/            # Generic framework + 9 protocol connectors
│   │   ├── mod.rs              # BruteForceAction<C: Connector>
│   │   ├── ssh.rs              # russh (pure Rust)
│   │   ├── ftp.rs              # suppaftp (pure Rust)
│   │   ├── telnet.rs           # raw TCP (pure Rust)
│   │   ├── sql.rs              # mysql CLI
│   │   ├── postgres.rs         # psql CLI
│   │   ├── mongo.rs            # mongosh CLI
│   │   ├── redis.rs            # raw TCP RESP protocol (pure Rust)
│   │   ├── smb.rs              # smbclient CLI
│   │   └── rdp.rs              # xfreerdp CLI
│   └── exfiltrate/             # 9 data theft modules (child actions)
├── orchestrator/               # Main loop, action scheduling, retry logic
├── display/
│   ├── epd_v4.rs               # Waveshare 2.13" V4 SPI driver (rppal)
│   └── renderer.rs             # UI rendering (imageproc + ab_glyph)
└── web/
    ├── server.rs               # Axum (port 8000, gzip, static files)
    └── handlers.rs             # 25+ API endpoints
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
| `portlist` | 42 ports | List of ports to scan |
| `epd_type` | `epd2in13_V4` | e-Paper display model |

## System Dependencies

The install script (`deploy/install.sh`) installs these automatically, or install manually:

```bash
sudo apt-get install -y nmap smbclient sshpass wget zip \
    redis-tools mysql-client postgresql-client xfreerdp2-x11 \
    network-manager
```

## Disclaimer

This project is strictly for **educational purposes** and **authorized security testing**. Unauthorized use for malicious activities is prohibited and may be prosecuted by law. The authors disclaim any responsibility for misuse.

## License

MIT License. See [LICENSE](LICENSE) for details.

Based on [infinition/Bjorn](https://github.com/infinition/Bjorn) (Python).
