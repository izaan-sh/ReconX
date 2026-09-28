"""
ReconX — CVE Lookup Module
Queries the NIST NVD API for known CVEs based on keyword/service input.
Also maps open ports to common CVE searches.
"""

import urllib.request
import urllib.parse
import json
import time
from modules.banner import info, success, warn, error, muted, finding, data, section_header, Colors as C

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common service → CVE search keywords
SERVICE_CVE_MAP = {
    21:    ["vsftpd", "proftpd", "filezilla ftp"],
    22:    ["openssh"],
    23:    ["telnet"],
    25:    ["postfix", "sendmail", "opensmtpd"],
    80:    ["apache httpd", "nginx", "iis"],
    110:   ["dovecot pop3"],
    143:   ["dovecot imap"],
    443:   ["openssl", "apache ssl", "nginx ssl"],
    445:   ["smb", "samba", "ms17-010"],
    1433:  ["microsoft sql server"],
    3306:  ["mysql", "mariadb"],
    3389:  ["rdp", "remote desktop"],
    5432:  ["postgresql"],
    5900:  ["vnc", "libvncserver"],
    6379:  ["redis"],
    8080:  ["apache tomcat", "jetty"],
    27017: ["mongodb"],
}

CVSS_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.CYAN,
    "LOW":      C.MUTED,
    "NONE":     C.MUTED,
}


def get_severity(score):
    if score >= 9.0:   return "CRITICAL"
    elif score >= 7.0: return "HIGH"
    elif score >= 4.0: return "MEDIUM"
    elif score > 0:    return "LOW"
    return "NONE"


def fetch_cves(keyword, results_per_page=5):
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "noRejected": ""
    })
    url = f"{NVD_API_BASE}?{params}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "ReconX/1.0",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return None


def parse_cve(vuln):
    cve_id = vuln.get("cve", {}).get("id", "N/A")
    desc_list = vuln.get("cve", {}).get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")
    desc = desc[:120] + "..." if len(desc) > 120 else desc

    metrics = vuln.get("cve", {}).get("metrics", {})
    score = 0.0
    severity = "NONE"

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            if "cvssData" in m:
                score = m["cvssData"].get("baseScore", 0.0)
                severity = m["cvssData"].get("baseSeverity", get_severity(score))
                break

    published = vuln.get("cve", {}).get("published", "")[:10]
    return {"id": cve_id, "score": score, "severity": severity, "description": desc, "published": published}


class CVELookup:
    def __init__(self, target, keywords=None, ports=None):
        self.target = target
        self.custom_keywords = keywords or []
        self.ports = ports or []

    def _build_search_terms(self):
        terms = []
        for kw in self.custom_keywords:
            terms.append(kw)
        for port in self.ports:
            if port in SERVICE_CVE_MAP:
                terms.extend(SERVICE_CVE_MAP[port])
        if not terms:
            terms = ["apache httpd", "openssh", "nginx", "openssl"]
        return list(dict.fromkeys(terms))

    def run(self):
        section_header("CVE LOOKUP — NVD DATABASE")
        results_data = {"cves": [], "findings": [], "summary": ""}

        if self.custom_keywords:
            terms = self.custom_keywords
        else:
            terms = self._build_search_terms()[:4]

        info("Querying NIST NVD API (https://nvd.nist.gov)")
        info(f"Search terms: {', '.join(terms)}")
        print()

        all_cves = []

        for term in terms:
            muted(f"Searching: '{term}'...")
            data_raw = fetch_cves(term, results_per_page=4)
            time.sleep(0.7)

            if not data_raw:
                warn(f"  Could not fetch CVEs for '{term}' — NVD may be rate-limiting")
                continue

            vulns = data_raw.get("vulnerabilities", [])
            if not vulns:
                muted(f"  No CVEs found for '{term}'")
                continue

            print(f"\n  {C.PURPLE}── Results for: {term} ({data_raw.get('totalResults', 0)} total) ──{C.RESET}")
            print(f"  {'CVE ID':<20} {'SCORE':<8} {'SEVERITY':<10} {'PUBLISHED':<12} DESCRIPTION")
            print(f"  {'─'*20} {'─'*8} {'─'*10} {'─'*12} {'─'*35}")

            for vuln in vulns[:4]:
                cve = parse_cve(vuln)
                sev = cve["severity"]
                col = CVSS_COLORS.get(sev, C.RESET)
                score_str = f"{cve['score']:.1f}"
                print(f"  {C.CYAN}{cve['id']:<20}{C.RESET} {col}{score_str:<8}{sev:<10}{C.RESET} {cve['published']:<12} {C.MUTED}{cve['description']}{C.RESET}")

                all_cves.append(cve)
                results_data["cves"].append(cve)

                if cve["severity"] in ("CRITICAL", "HIGH"):
                    msg = f"{cve['id']} (CVSS {cve['score']}) — {cve['description'][:80]}"
                    finding(msg)
                    results_data["findings"].append(msg)

        print()
        critical = sum(1 for c in all_cves if c["severity"] == "CRITICAL")
        high = sum(1 for c in all_cves if c["severity"] == "HIGH")

        if critical > 0:
            warn(f"{critical} CRITICAL severity CVE(s) found — immediate review required")
        if high > 0:
            warn(f"{high} HIGH severity CVE(s) found")

        success(f"CVE lookup complete — {len(all_cves)} CVE(s) retrieved across {len(terms)} service(s)")
        results_data["summary"] = f"{len(all_cves)} CVEs found — {critical} CRITICAL, {high} HIGH"

        return results_data
