# Linux Log Analyzer (`logan`)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#)
[![Interface](https://img.shields.io/badge/UI-TUI%20Web%20Dashboard-cyan.svg)](#)

A high-performance, **zero-dependency** Python log intelligence suite and mission-control web dashboard for analyzing Linux authentication, system, and web access logs. Features brute-force detection, compromise indicators, error tracking, and hourly activity visualization.

---

## Highlights

- **Zero External Dependencies:** Built entirely with Python's standard library (`http.server`, `argparse`, `dataclasses`, `collections`, `gzip`) and vanilla JavaScript / SVG. No npm, no pip dependencies, no CDN requests, completely offline-capable.
- **Multi-Source Ingestion:** Ingests Linux authentication logs (`auth.log`, `secure`), system logs (`syslog`, `messages`), and web server logs (Nginx / Apache combined format). Supports `.gz` compressed logs transparently.
- **Security & Threat Detection:**
  - Automated brute-force detection with customizable failure thresholds.
  - Possible compromise alerts (identifies IPs that succeeded after multiple failed attempts).
  - Top attacking IP addresses and most targeted usernames.
- **Mission Control Web Dashboard:**
  - Premium terminal / TUI-inspired interface (custom dark mode and high-contrast light mode).
  - Drag-and-drop log uploader with auto-detection.
  - Interactive hourly activity charts and daily event breakdowns.
  - One-click report export in formatted text and structured JSON.
- **Strict Security Defaults:** Hardened Content Security Policy (`default-src 'self'`), loopback binding protection, and zero HTML injection (all log data rendered safely via `textContent`).

---

## Dashboard Preview

The web dashboard provides a high-density, terminal-style telemetry view of your server's security posture:

- **Telemetry KPIs:** Real-time counters for failed logins, successful logins, system errors, web traffic, and flagged IPs.
- **Security Alerts:** Immediate indicators for brute-force attacks and suspicious account compromises.
- **Time Distribution:** Responsive SVG line charts showing activity curves across 24 hours of the day.
- **Ranked Tables:** Visual progress bars for top IP addresses, target users, authentication methods, and failing HTTP endpoints.

---

## Installation

### Prerequisites
- Python 3.10 or higher

### Setup
Clone the repository and install the package in editable mode:

```bash
git clone https://github.com/kumaradoss16/linux-log-analyzer.git
cd linux-log-analyzer

# Optional: Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .
```

---

## Usage

### 1. Command-Line Interface (`logan`)

Analyze log files directly in your terminal:

```bash
# Analyze authentication logs
logan --auth /var/log/auth.log

# Analyze multiple log sources together
logan --auth /var/log/auth.log --system /var/log/syslog --web /var/log/nginx/access.log

# Read gzip-compressed logs directly
logan --auth /var/log/auth.log.1.gz --web /var/log/nginx/access.log.2.gz

# Adjust brute-force threshold and top-N ranking
logan --auth samples/auth.log --threshold 10 --top 20

# Export analysis as JSON or save report to file
logan --auth samples/auth.log --format json -o security-report.json
logan --auth samples/auth.log --system samples/syslog -o report.txt
```

#### CLI Options
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--auth FILE [FILE ...]` | One or more authentication log files | `[]` |
| `--system FILE [FILE ...]`| One or more system log files (`syslog`) | `[]` |
| `--web FILE [FILE ...]` | One or more Apache/Nginx combined access logs | `[]` |
| `--top INT` | Number of rows in top-N tables | `10` |
| `--threshold INT` | Failed logins from one IP before flagging brute-force | `5` |
| `--year INT` | Base year for syslog timestamps (omitted in syslog format) | Current Year |
| `--format {text,json}` | Report format | `text` |
| `-o, --output FILE` | Write report to file instead of standard output | `stdout` |

---

### 2. Web Dashboard (`logan serve` or `logan-web`)

Launch the local interactive dashboard:

```bash
# Start dashboard and open directly in default browser
logan serve --open

# Preload sample or server logs on startup
logan serve --auth samples/auth.log --system samples/syslog --web samples/access.log

# Bind to a custom port or address
logan serve --host 127.0.0.1 --port 8080
```

Once running, navigate to `http://127.0.0.1:8000` to interactively upload logs, tune filters, and export reports.

---

## Project Structure

```text
linux-log-analyzer/
├── pyproject.toml              # Build configuration and CLI entry points
├── README.md                   # Project documentation
├── samples/                    # Sample log files for testing & demonstration
│   ├── access.log              # Nginx web access log sample
│   ├── auth.log                # Linux authentication / SSH log sample
│   └── syslog                  # System daemon and kernel log sample
└── src/
    └── log_analyzer/
        ├── __init__.py         # Package version and metadata
        ├── analyzer.py         # Log stream aggregation, metrics & stats engine
        ├── cli.py              # Command-line interface parser and entrypoint
        ├── models.py           # Dataclasses and enums (Source, Kind, Event)
        ├── parsers.py          # Regex parsers for auth, syslog, and web logs
        ├── report.py           # Text and JSON report formatters
        ├── web.py              # Stdlib HTTP server, REST API & file manager
        └── static/
            ├── index.html      # Dashboard semantic markup
            ├── style.css       # Terminal/TUI design system (Dark & Light modes)
            └── app.js          # Reactive dashboard frontend (Vanilla JS & SVG)
```

---

## Security & Privacy Notice

- **Local Execution:** All log parsing and analysis occurs entirely on your machine. No telemetry, analytical beacons, or external network requests are made.
- **Content Security Policy:** Served with strict `default-src 'self'` headers preventing cross-site scripting and external resource loading.
- **Authorization:** Only analyze log files that you own or have explicit authorization to inspect.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
