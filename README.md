# ProcX

A lightweight macOS process monitor with a web-based dashboard. Run it and open your browser to see real-time CPU, memory, and port usage for all running processes.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![macOS](https://img.shields.io/badge/Platform-macOS-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **System Overview** — Real-time CPU and memory usage at a glance
- **Process Grouping** — Automatically groups related processes (e.g., all Cursor/VS Code helpers shown as one entry)
- **Port Detection** — Shows which ports each process is listening on
- **Smart Recommendations** — Identifies idle apps wasting memory, CPU hogs, and stale processes
- **Kill Processes** — Send SIGTERM/SIGKILL to processes directly from the UI
- **Zero Dependencies** — Pure Python standard library, no `pip install` needed

## Quick Start

```bash
python3 server.py
```

Then open [http://localhost:9876](http://localhost:9876).

## How It Works

- `server.py` — HTTP server that exposes process data via a JSON API (`/api/data`, `/api/processes`, `/api/kill`)
- `index.html` — Single-page dashboard that polls the API and renders the UI

The server uses `ps`, `lsof`, `vm_stat`, and `top` under the hood to gather system information. No external packages required.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/data` | Full dashboard data (processes, groups, stats, recommendations) |
| GET | `/api/processes` | Raw process list |
| POST | `/api/kill` | Kill process(es) by PID — body: `{"pids": [1234], "signal": "TERM"}` |

## Requirements

- macOS (uses macOS-specific commands like `vm_stat`, `sysctl`)
- Python 3.8+
