# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0-alpha.5] - 2026-04-02

### Added
- **Web UI**: manual attack execution (`POST /execute_manual_attack`), backup restore (`POST /restore`)
- **Display**: two-layer rendering (dithered icons + crisp 1-bit text), Floyd-Steinberg dithering
- **Display**: comment engine with themed random quotes, animated status character images
- **Display**: multi-EPD support (V2, V3, V4)
- **CLI**: `bjorn --version` flag
- **DB**: `host_by_ip()` query, PAN connected display state

### Fixed
- Static file serving root path (fixes broken images/CSS/JS in web UI)
- HTML page redirects (`/loot.html` → `/web/loot.html`)

### Changed
- Release artifacts now include version number (e.g. `bjorn-aarch64-v1.0.0-alpha.5`)
- Upgrade GitHub Actions (checkout v6, upload-artifact v7, download-artifact v8)

## [1.0.0-alpha.4] - 2026-04-01

### Added
- Multi-EPD display support (V2, V3, V4)
- CI/CD pipeline with cross-compilation
- Display rendering optimizations

## [1.0.0-alpha.3] - 2026-03-31

### Added
- SNMP, VNC, MQTT, HTTP Basic Auth attack modules (14 brute force + 13 exfiltration = 27 total)
- LLM integration with 3-tier cascade (Ollama → Anthropic → OpenAI)
- Sentinel network watchdog (new devices, ARP spoofing, port changes)
- Web UI with 30+ API endpoints
- e-Paper Waveshare 2.13" V4 display driver
- SQLite knowledge base replacing CSV files
