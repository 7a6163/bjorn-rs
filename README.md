# Bjorn (Rust Edition)

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Alpha-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Bjorn 的 Rust 重寫版本 — 一個自主網路掃描、弱點評估與攻擊性安全工具，專為 Raspberry Pi + 2.13 吋 e-Paper HAT 設計。

> **Rewrite of [infinition/Bjorn](https://github.com/infinition/Bjorn) (Python) in Rust for better performance on constrained hardware.**

## Why Rust?

| | Python 版 | Rust 版 |
|---|---|---|
| 部署大小 | ~100MB (runtime + deps) | **6.7MB** (單一 binary) |
| 啟動時間 | ~10-15 秒 | **< 3 秒** |
| 記憶體 | ~100MB+ (pandas, etc.) | **< 50MB** |
| 並發模型 | threading + GIL | tokio async |
| 資料庫 | CSV (無並發保護) | SQLite WAL (ACID) |
| 部署方式 | pip install + 大量依賴 | scp 一個檔案 |
| Actions | 12 | **18** (+PostgreSQL, MongoDB, Redis) |

## Features

- **Network Scanning** — nmap host discovery + async TCP port scan
- **Vulnerability Assessment** — nmap + vulners.nse script
- **Brute Force** — SSH, FTP, Telnet, SMB, RDP, MySQL, PostgreSQL, MongoDB, Redis
- **Data Exfiltration** — SFTP, FTP download, SQL dump, SMB share grab, Redis dump
- **e-Paper Display** — Waveshare 2.13" V4, real-time Tamagotchi-style UI
- **Web Interface** — port 8000, config management, live monitoring, loot viewer
- **Headless Mode** — 沒有 e-Paper 也能跑（只輸出 PNG 給 Web UI）

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
# 從 release 下載 binary（或自行編譯，見下方）
scp bjorn-aarch64 bjorn@<PI_IP>:/home/bjorn/bjorn
scp -r deploy/ bjorn@<PI_IP>:/home/bjorn/deploy/

# SSH 進 Pi
ssh bjorn@<PI_IP>
chmod +x /home/bjorn/bjorn
sudo /home/bjorn/deploy/install.sh

# 啟動
sudo systemctl start bjorn.service
```

### Manual Run

```bash
sudo BJORN_ROOT=/home/bjorn/Bjorn RUST_LOG=bjorn=debug /home/bjorn/bjorn
```

### Service Control

```bash
sudo systemctl start bjorn.service     # 啟動
sudo systemctl stop bjorn.service      # 停止
sudo systemctl status bjorn.service    # 狀態
sudo journalctl -u bjorn.service -f    # 即時 log
```

### Web UI

瀏覽器開啟 `http://<PI_IP>:8000`

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

1. **Startup** — 載入設定、開啟 SQLite KB、啟動 3 個 async task
2. **Network Scan** — `nmap -sn` 發現主機 → async TCP port scan → 寫入 KB
3. **Orchestrator Loop** — 遍歷 alive hosts → port 匹配 → parent 依賴檢查 → 重試延遲 → 執行 action
4. **Brute Force** — 載入 wordlist → 並發嘗試所有帳密組合 → 成功寫入 credentials 表
5. **Exfiltration** — 用破解的帳密連線 → 搜尋/下載目標檔案
6. **Display** — 每秒渲染 UI → SPI 送到 e-Paper → 同時存 PNG 給 Web UI
7. **Web Server** — Axum 提供即時監控、設定管理、戰果查看

### Knowledge Base (SQLite)

取代 Python 版的 CSV，提供 ACID 交易和並發安全：

| Table | 用途 |
|-------|------|
| `hosts` | 發現的主機（MAC, IP, hostname, ports, alive） |
| `action_results` | 每次 action 執行結果（成功/失敗 + 時間戳） |
| `credentials` | 破解的帳密（自動去重） |
| `vulnerabilities` | 發現的弱點（CVE, severity） |

## Configuration

設定檔位於 `$BJORN_ROOT/config/shared_config.json`，也可以透過 Web UI 修改。

關鍵設定：

| 設定 | 預設值 | 說明 |
|------|--------|------|
| `manual_mode` | `false` | 手動模式（暫停自動掃描） |
| `scan_interval` | `180` | 掃描間隔（秒） |
| `scan_vuln_running` | `false` | 是否啟用弱點掃描 |
| `retry_failed_actions` | `true` | 失敗的 action 是否重試 |
| `failed_retry_delay` | `600` | 失敗重試延遲（秒） |
| `portlist` | 42 ports | 要掃描的 port 列表 |
| `epd_type` | `epd2in13_V4` | e-Paper 螢幕型號 |

## System Dependencies

安裝腳本 (`deploy/install.sh`) 會自動安裝，或手動：

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
