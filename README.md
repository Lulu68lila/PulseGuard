# PulseGuard Antivirus

PulseGuard is a modular, high-performance antivirus application built with Python 3.11+.

## Architecture & Subsystems
- **Desktop GUI (`gui/`)**: Cyberpunk Glassmorphism desktop interface powered by Electron and HTML5/CSS, featuring a reactive rotating radar shield, interactive file scanner, process inspector, quarantine vault management, and live audit terminal.
- **REST API Bridge (`src/pulseguard/api/`)**: Local multithreaded REST API server on `http://127.0.0.1:48201` bridging the Electron UI with the Python antivirus core.
- **Core Engine (`src/pulseguard/engine/`)**: Signature-based hash scanning, byte pattern matching, and heuristic/entropy analysis.
- **Quarantine Subsystem (`src/pulseguard/quarantine/`)**: AES-256-GCM encrypted isolation vault, catalog registry, restore and shred capabilities.
- **Real-Time Watcher (`src/pulseguard/watcher/`)**: Low-latency directory and filesystem monitoring with event debouncing.
- **CLI & Service (`src/pulseguard/cli/`, `src/pulseguard/service/`)**: Command-line application, interactive status, and background service runner.
- **Shared Contracts (`src/pulseguard/core/models.py`)**: Unified domain data models across all subsystems.

## Launching the Desktop Application (v0.2.0)
Double-click `start-gui.bat` or run from your terminal:
```bash
cd gui
npm start
```
The Electron desktop window will automatically launch and supervise the Python backend API in the background.

## CLI Usage
```bash
# Launch the API server
python -m pulseguard serve

# Scan a file or directory
python -m pulseguard scan C:\Users\YourUser\Downloads

# Start real-time monitoring
python -m pulseguard watch C:\Users\YourUser\Downloads --quarantine
```

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
