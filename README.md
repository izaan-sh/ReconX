# ReconX v2 — Interactive Security Scanner

> Author: Izaan Shumaiz | Security Portfolio Project

A web-based interactive security scanner. Run one command, open your browser, and get a full visual dashboard with beginner-friendly explanations for every finding.

---

## Quick Start

```bash
# 1. Install Flask (only dependency)
pip3 install flask

# 2. Run the server
python3 reconx.py

# 3. Open your browser
# Go to: http://localhost:5000
```

---

## Features

- **Interactive browser dashboard** — no terminal knowledge needed
- **"Scan this machine" button** — auto-detects your own IP
- **Named scans** — give each scan a name so reports are easy to identify
- **Beginner-friendly findings** — every issue explained in plain English
- **How-to-fix instructions** — step-by-step fix for every finding
- **Risk-sorted results** — Critical issues always shown first
- **Scan history** — all past scans saved and accessible
- **HTML + TXT reports** — downloadable reports named by scan name

## Modules

| Module | What it does |
|--------|-------------|
| Port Scan | Checks which services/ports are open on the target |
| HTTP Headers | Checks if the web server has security protections enabled |
| DNS Lookup | Finds all DNS records and hidden subdomains |
| CVE Check | Looks up known vulnerabilities from the NIST database |
| WHOIS | Finds domain registration and ownership info |

## Legal

Only scan systems you own or have explicit permission to test.
