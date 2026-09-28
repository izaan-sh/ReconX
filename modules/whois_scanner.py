"""
ReconX — WHOIS Scanner Module
Performs WHOIS lookups using system whois or socket-based fallback.
"""

import subprocess
import socket
import re
from modules.banner import info, success, warn, error, muted, finding, data, section_header, Colors as C

WHOIS_PORT = 43
WHOIS_SERVER = "whois.iana.org"

INTERESTING_FIELDS = [
    "Registrar", "Registrar URL", "Updated Date", "Creation Date",
    "Registry Expiry Date", "Registrant Organization", "Registrant Country",
    "Admin Email", "Name Server", "DNSSEC", "Registrant State/Province",
    "Tech Email",
]


def _run_whois_cmd(target):
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _socket_whois(target, server=WHOIS_SERVER):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, WHOIS_PORT))
        sock.send(f"{target}\r\n".encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _extract_field(raw, field_name):
    pattern = re.compile(rf"^{re.escape(field_name)}:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    matches = pattern.findall(raw)
    return [m.strip() for m in matches if m.strip()]


class WhoisScanner:
    def __init__(self, target):
        self.target = target
        self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    def run(self):
        section_header("WHOIS LOOKUP")
        results_data = {"whois_data": {}, "findings": [], "summary": ""}

        info(f"Target: {self.domain}")
        print()

        raw = _run_whois_cmd(self.domain)
        if not raw:
            muted("System 'whois' command not available, trying socket fallback...")
            raw = _socket_whois(self.domain)

        if not raw:
            error(f"Could not retrieve WHOIS data for {self.domain}")
            results_data["summary"] = "WHOIS lookup failed"
            return results_data

        print(f"  {C.PURPLE}── WHOIS Record ──{C.RESET}\n")

        found_any = False
        for field in INTERESTING_FIELDS:
            values = _extract_field(raw, field)
            if values:
                for val in values[:2]:
                    # Redact emails partially
                    if "@" in val and "Email" in field:
                        parts = val.split("@")
                        val = parts[0][:3] + "***@" + parts[1] if len(parts) == 2 else val
                    data(field, val)
                    results_data["whois_data"].setdefault(field, []).append(val)
                    found_any = True

        if not found_any:
            muted("Standard WHOIS fields not found — domain may be privacy-protected or using RDAP")
            muted("Raw output excerpt:")
            for line in raw.split("\n")[:25]:
                if line.strip() and not line.startswith("%") and not line.startswith("#"):
                    print(f"  {C.MUTED}  {line.strip()}{C.RESET}")

        # Check expiry
        expiry_vals = _extract_field(raw, "Registry Expiry Date") or _extract_field(raw, "Expiry Date")
        if expiry_vals:
            print(f"\n  {C.PURPLE}── Expiry Check ──{C.RESET}")
            data("Expiry Date", expiry_vals[0])
            try:
                from datetime import datetime
                exp_str = expiry_vals[0][:10]
                exp_date = datetime.strptime(exp_str, "%Y-%m-%d")
                days_left = (exp_date - datetime.now()).days
                if days_left < 30:
                    finding(f"Domain expires in {days_left} days — possible takeover/lapse risk!")
                    results_data["findings"].append(f"Domain expires in {days_left} days")
                elif days_left < 90:
                    warn(f"Domain expires in {days_left} days")
                else:
                    muted(f"Domain valid for ~{days_left} more days")
            except Exception:
                pass

        # Name servers
        ns_vals = _extract_field(raw, "Name Server")
        if ns_vals:
            print(f"\n  {C.PURPLE}── Name Servers ──{C.RESET}")
            for ns in list(set(ns_vals))[:4]:
                data("NS", ns)

        # DNSSEC
        dnssec = _extract_field(raw, "DNSSEC")
        if dnssec:
            val = dnssec[0].lower()
            print(f"\n  {C.PURPLE}── DNSSEC ──{C.RESET}")
            if "unsigned" in val or "unsigned" in val:
                warn("DNSSEC: unsigned — DNS spoofing attacks may be possible")
                results_data["findings"].append("DNSSEC not configured")
            else:
                data("DNSSEC", dnssec[0])

        print()
        success("WHOIS lookup complete")
        results_data["summary"] = f"WHOIS data retrieved for {self.domain}"

        return results_data
