#!/usr/bin/env python3
"""
ReconX - Interactive Security Scanner
Run: python3 reconx.py
Then open: http://localhost:5000
"""

import json
import socket
import threading
import time
import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory

from modules.port_scanner import PortScanner
from modules.header_scanner import HeaderScanner
from modules.dns_scanner import DNSScanner
from modules.cve_lookup import CVELookup
from modules.whois_scanner import WhoisScanner
from modules.report import ReportGenerator
from modules.explainer import explain_findings

app = Flask(__name__, static_folder="static")

# Store scan jobs in memory
scan_jobs = {}
# Track used scan names for uniqueness enforcement
used_scan_names = set()


def get_own_ip():
    """Get this machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_scan_job(job_id, target, modules, scan_name):
    job = scan_jobs[job_id]
    job["status"] = "running"
    job["started_at"] = datetime.now().isoformat()
    job["log"] = []
    job["results"] = {}

    report = ReportGenerator(target, scan_name)

    def log(msg, level="info"):
        entry = {"msg": msg, "level": level, "time": datetime.now().strftime("%H:%M:%S")}
        job["log"].append(entry)

    module_map = {
        "ports":   ("Port Scan",       PortScanner),
        "headers": ("HTTP Headers",    HeaderScanner),
        "dns":     ("DNS Lookup",      DNSScanner),
        "cve":     ("CVE Check",       CVELookup),
        "whois":   ("WHOIS Info",      WhoisScanner),
    }

    run_modules = list(module_map.keys()) if "full" in modules else modules

    for mod_key in run_modules:
        if mod_key not in module_map:
            continue
        name, cls = module_map[mod_key]
        log(f"Starting {name}...")
        job["current_module"] = name
        try:
            scanner = cls(target)
            results = scanner.run()
            job["results"][mod_key] = results
            report.add_section(name, results)
            log(f"{name} complete — {results.get('summary', '')}", "success")
        except Exception as e:
            log(f"{name} failed: {str(e)}", "error")
            job["results"][mod_key] = {"error": str(e), "summary": f"Module failed: {e}"}

    # Generate beginner-friendly explanations
    log("Generating plain-English explanations...")
    job["explanations"] = explain_findings(job["results"])

    # Save report
    try:
        paths = report.save()
        job["report_paths"] = paths
        log(f"Report saved", "success")
    except Exception as e:
        log(f"Report save failed: {e}", "error")

    job["status"] = "complete"
    job["completed_at"] = datetime.now().isoformat()
    job["current_module"] = None


# ── Routes ──────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "dashboard.html")


@app.route("/api/myip")
def my_ip():
    ip = get_own_ip()
    hostname = socket.gethostname()
    return jsonify({"ip": ip, "hostname": hostname})


@app.route("/api/network/discover")
def discover_network():
    """Quick ARP-style discovery of devices on local network."""
    import subprocess, re
    own_ip = get_own_ip()
    devices = [{"ip": own_ip, "hostname": socket.gethostname(), "label": "This Machine"}]
    try:
        # Use arp -a to find recently seen devices
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                if ip != own_ip and not ip.startswith("224.") and not ip.endswith(".255"):
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip
                    devices.append({"ip": ip, "hostname": hostname, "label": hostname})
    except Exception:
        pass
    return jsonify({"devices": devices})


@app.route("/api/scan/check_name", methods=["POST"])
def check_name():
    name = (request.json or {}).get("name", "").strip().lower()
    exists = name in used_scan_names
    return jsonify({"exists": exists})


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.json
    target = data.get("target", "").strip()
    modules = data.get("modules", ["full"])
    scan_name = data.get("scan_name", "").strip()

    if not target:
        return jsonify({"error": "Please enter a target (IP address or domain)."}), 400

    if not scan_name:
        return jsonify({"error": "Please give this scan a name before starting."}), 400

    if scan_name.lower() in used_scan_names:
        return jsonify({"error": f'A scan named "{scan_name}" already exists. Please choose a different name.'}), 409

    used_scan_names.add(scan_name.lower())

    # If scanning self, resolve to own IP
    if target in ("self", "localhost", "127.0.0.1", socket.gethostname()):
        target = get_own_ip()

    job_id = f"scan_{int(time.time()*1000)}"
    scan_jobs[job_id] = {
        "id": job_id,
        "target": target,
        "scan_name": scan_name,
        "modules": modules,
        "status": "queued",
        "log": [],
        "results": {},
        "explanations": [],
        "current_module": None,
        "report_paths": None,
        "created_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=run_scan_job, args=(job_id, target, modules, scan_name))
    thread.daemon = True
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>")
def get_scan(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/scans")
def list_scans():
    scans = []
    for job in scan_jobs.values():
        scans.append({
            "id": job["id"],
            "target": job["target"],
            "scan_name": job["scan_name"],
            "status": job["status"],
            "created_at": job["created_at"],
            "completed_at": job.get("completed_at"),
        })
    return jsonify(sorted(scans, key=lambda x: x["created_at"], reverse=True))


@app.route("/api/reports")
def list_reports():
    reports = []
    if os.path.exists("reports"):
        for f in sorted(os.listdir("reports"), reverse=True):
            if f.endswith(".html"):
                reports.append({"name": f, "path": f"/reports/{f}"})
    return jsonify(reports)


@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory("reports", filename)


if __name__ == "__main__":
    print("\n  ReconX — Interactive Security Scanner")
    print(f"  Open your browser at: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
