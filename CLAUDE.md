# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bjorn (Rust Edition) is a rewrite of the Python Bjorn project — an autonomous network scanning, vulnerability assessment, and offensive security tool for Raspberry Pi with e-Paper display. This is an authorized-testing-only educational security tool.

## Build & Test

```bash
cargo build --release          # Host build
cargo test                     # Run all tests
make build-pi-zero             # Cross-compile for Pi Zero W (ARMv6, requires `cross`)
make build-pi64                # Cross-compile for Pi Zero W2 / Pi 3/4/5 (AArch64)
make deploy PI=bjorn@10.0.0.5  # Deploy to Pi via SSH
```

Cross-compilation uses [cross](https://github.com/cross-rs/cross) (Docker-based). Install: `cargo install cross`.

## Architecture

### Runtime Model

`main.rs` starts a tokio runtime with 3 async tasks:
1. **Orchestrator** — scans network, runs actions, manages retry logic
2. **Display** — renders to e-Paper HAT (Phase 2, placeholder)
3. **Web server** — Axum on port 8000, serves static UI + JSON API

### State Management

Python's `SharedData` god-object is split into:
- `config::BjornConfig` — immutable, loaded from `shared_config.json`, hot-swappable via `ArcSwap`
- `config::PathConfig` — all filesystem paths, immutable
- `state::AppState` — `Arc`-shared, holds config + `RwLock<OrchestratorStatus>` + `RwLock<DisplayData>` + KB + `CancellationToken`
- `state::KnowledgeBase` — SQLite (WAL mode) replacing CSV `netkb.csv`

### Action System

`actions::Action` trait (dyn-compatible) with static registry in `build_action_registry()`.

**18 registered actions:**
- Network scanning (`scanning.rs`) and vuln scanning (`vuln_scanner.rs`) are used directly by the orchestrator
- 9 brute-force actions use the generic `BruteForceAction<C: Connector>` framework — each connector only implements `try_connect()`
- 9 exfiltrate actions are child actions that depend on a parent brute-force succeeding

### Knowledge Base (SQLite)

4 tables: `hosts`, `action_results`, `credentials`, `vulnerabilities`. Replaces the CSV-based netkb with proper ACID transactions and concurrent-safe WAL mode.

### Web Server

Axum with `tower-http` for gzip + static file serving. All Python API routes are ported. Static frontend files live in `web/` (reused from Python project).

## Key Directories

```
src/
├── config/          # BjornConfig (serde) + PathConfig
├── state/           # AppState + SQLite KnowledgeBase
├── actions/
│   ├── scanning.rs  # nmap -sn + async TCP port scan
│   ├── vuln_scanner.rs
│   ├── brute_force/ # Generic framework + 9 connectors
│   └── exfiltrate/  # 9 data theft modules
├── orchestrator/    # Main loop, scheduling, retry logic
└── web/             # Axum server + API handlers
deploy/              # systemd service + install script
```

## Cross-Compilation Notes

- SQLite uses `bundled` feature (compiles from C source, no system dep)
- TLS uses `rustls` (pure Rust, no OpenSSL needed)
- SSH uses `russh` (pure Rust)
- SMB/RDP/SQL/Postgres/Mongo shell out to system CLIs (smbclient, xfreerdp, mysql, psql, mongosh)
