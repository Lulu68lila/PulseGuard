# PulseGuard Antivirus

PulseGuard is a modular, high-performance antivirus application built with Python 3.11+.

## Architecture & Subsystems
- **Core Engine (`src/pulseguard/engine/`)**: Signature-based hash scanning, byte pattern matching, and heuristic/entropy analysis.
- **Quarantine Subsystem (`src/pulseguard/quarantine/`)**: AES-256-GCM encrypted isolation vault, catalog registry, restore and shred capabilities.
- **Real-Time Watcher (`src/pulseguard/watcher/`)**: Low-latency directory and filesystem monitoring with event debouncing.
- **CLI & Service (`src/pulseguard/cli/`, `src/pulseguard/service/`)**: Command-line application, interactive status, and background service runner.
- **Shared Contracts (`src/pulseguard/core/models.py`)**: Unified domain data models across all subsystems.

## Installation & Setup
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
pip install -e .[dev]
```

## Running Tests
```bash
python -m pytest tests/ -v
```
