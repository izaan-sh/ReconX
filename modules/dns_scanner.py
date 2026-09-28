"""
ReconX — DNS Enumeration Module
Performs DNS record lookups: A, AAAA, MX, NS, TXT, CNAME, SOA.
Also checks for common subdomains.
"""

import socket
import subprocess
import sys
from modules.banner import info, success, warn, error, muted, finding, data, section_header, Colors as C

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
    "cdn", "static", "images", "blog", "shop", "store", "portal",
    "vpn", "remote", "webmail", "ns1", "ns2", "smtp", "pop", "imap",
    "dashboard", "app", "beta", "old", "backup", "secure", "login",
]


def _run_dig(target, record_type):
    try:
        result = subprocess.run(
            ["dig", "+short", record_type, target],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        return lines
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _socket_resolve(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


class DNSScanner:
    def __init__(self, target):
        self.target = target
        # strip protocol if present
        self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    def _lookup_a(self):
        records = []
        try:
            infos = socket.getaddrinfo(self.domain, None)
            ips = list(set(i[4][0] for i in infos))
            for ip in ips:
                records.append(ip)
        except Exception:
            pass
        if not records:
            ip = _socket_resolve(self.domain)
            if ip:
                records.append(ip)
        return records

    def _lookup_with_dig(self, rtype):
        return _run_dig(self.domain, rtype)

    def _check_subdomains(self):
        found = []
        muted(f"Checking {len(COMMON_SUBDOMAINS)} common subdomains...")
        for sub in COMMON_SUBDOMAINS:
            hostname = f"{sub}.{self.domain}"
            ip = _socket_resolve(hostname)
            if ip:
                found.append((hostname, ip))
        return found

    def run(self):
        section_header("DNS ENUMERATION")
        results_data = {"records": {}, "subdomains": [], "findings": [], "summary": ""}

        info(f"Target domain: {self.domain}")
        print()

        # A records
        print(f"  {C.PURPLE}── A Records (IPv4) ──{C.RESET}")
        a_records = self._lookup_a()
        if a_records:
            for ip in a_records:
                data("A", ip)
                results_data["records"].setdefault("A", []).append(ip)
        else:
            warn("No A records found")

        # AAAA records
        aaaa = self._lookup_with_dig("AAAA")
        if aaaa:
            print(f"\n  {C.PURPLE}── AAAA Records (IPv6) ──{C.RESET}")
            for r in aaaa:
                data("AAAA", r)
                results_data["records"].setdefault("AAAA", []).append(r)

        # MX records
        print(f"\n  {C.PURPLE}── MX Records (Mail) ──{C.RESET}")
        mx = self._lookup_with_dig("MX")
        if mx:
            for r in mx:
                data("MX", r)
                results_data["records"].setdefault("MX", []).append(r)
        else:
            muted("No MX records found via dig (dig may not be installed)")
            # fallback
            try:
                import subprocess
                r2 = subprocess.run(["nslookup", "-type=MX", self.domain],
                                    capture_output=True, text=True, timeout=5)
                lines = [l for l in r2.stdout.split("\n") if "mail exchanger" in l.lower()]
                for l in lines:
                    print(f"  {C.CYAN}  MX{C.RESET}                  {l.strip()}")
            except Exception:
                muted("nslookup fallback also unavailable")

        # NS records
        print(f"\n  {C.PURPLE}── NS Records (Nameservers) ──{C.RESET}")
        ns = self._lookup_with_dig("NS")
        if ns:
            for r in ns:
                data("NS", r)
                results_data["records"].setdefault("NS", []).append(r)
        else:
            muted("No NS records via dig")

        # TXT records
        print(f"\n  {C.PURPLE}── TXT Records ──{C.RESET}")
        txt = self._lookup_with_dig("TXT")
        if txt:
            for r in txt:
                data("TXT", r[:90])
                results_data["records"].setdefault("TXT", []).append(r)
                if "v=spf1" in r.lower():
                    muted("  ^ SPF record detected (email spoofing protection)")
                if "v=dmarc1" in r.lower():
                    muted("  ^ DMARC record detected")
                if "google-site-verification" in r.lower():
                    muted("  ^ Google site verification present")
        else:
            muted("No TXT records via dig")

        # CNAME
        print(f"\n  {C.PURPLE}── CNAME Records ──{C.RESET}")
        cname = self._lookup_with_dig("CNAME")
        if cname:
            for r in cname:
                data("CNAME", r)
                results_data["records"].setdefault("CNAME", []).append(r)
        else:
            muted("No CNAME records")

        # Subdomain enum
        print(f"\n  {C.PURPLE}── Subdomain Enumeration ──{C.RESET}")
        subs = self._check_subdomains()
        if subs:
            for hostname, ip in subs:
                print(f"  {C.GREEN}  [FOUND]{C.RESET} {hostname:<35} → {ip}")
                results_data["subdomains"].append({"subdomain": hostname, "ip": ip})
            finding(f"{len(subs)} subdomain(s) discovered — review for forgotten/exposed services")
            results_data["findings"].append(f"{len(subs)} subdomains found: {', '.join(h for h,_ in subs[:5])}")
        else:
            muted("No common subdomains resolved")

        print()
        total_records = sum(len(v) for v in results_data["records"].values())
        success(f"DNS enumeration complete — {total_records} records, {len(subs)} subdomains")
        results_data["summary"] = f"{total_records} DNS records found, {len(subs)} subdomains discovered"

        return results_data
