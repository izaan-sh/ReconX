"""
ReconX — HTTP Header Scanner Module
Fetches HTTP response headers and checks for missing/misconfigured security headers.
"""

import urllib.request
import urllib.error
import ssl
import socket
from modules.banner import info, success, warn, error, muted, finding, data, section_header, Colors as C

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — forces HTTPS connections",
        "risk": "HIGH",
        "missing_msg": "No HSTS header — site may be vulnerable to protocol downgrade attacks"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking via iframes",
        "risk": "MEDIUM",
        "missing_msg": "No X-Frame-Options — site may be vulnerable to clickjacking"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "risk": "MEDIUM",
        "missing_msg": "No X-Content-Type-Options — browser MIME sniffing enabled"
    },
    "Content-Security-Policy": {
        "desc": "Restricts resource loading, mitigates XSS",
        "risk": "HIGH",
        "missing_msg": "No CSP header — XSS attacks may be more effective"
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (older browsers)",
        "risk": "LOW",
        "missing_msg": "No X-XSS-Protection header (legacy, but worth noting)"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "risk": "LOW",
        "missing_msg": "No Referrer-Policy — referrer data may leak to third parties"
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access",
        "risk": "LOW",
        "missing_msg": "No Permissions-Policy header"
    },
}

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Cache",
    "CF-Ray", "X-Runtime", "X-Request-Id",
]

TECH_SIGNATURES = {
    "Apache": "Apache HTTP Server",
    "nginx": "NGINX",
    "Microsoft-IIS": "Microsoft IIS",
    "PHP": "PHP backend",
    "ASP.NET": "ASP.NET / .NET Framework",
    "Express": "Node.js / Express",
    "Django": "Python / Django",
    "WordPress": "WordPress CMS",
    "Drupal": "Drupal CMS",
    "Joomla": "Joomla CMS",
}


class HeaderScanner:
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout

    def _build_url(self, target):
        if target.startswith("http://") or target.startswith("https://"):
            return [target]
        return [f"https://{target}", f"http://{target}"]

    def fetch_headers(self, url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return dict(resp.headers), resp.status, url
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code, url
        except Exception as e:
            return None, None, url

    def run(self):
        section_header("HTTP HEADER ANALYSIS")
        results_data = {"headers": {}, "missing_security": [], "tech_stack": [], "findings": [], "summary": ""}

        urls = self._build_url(self.target)
        headers, status, used_url = None, None, None

        for url in urls:
            info(f"Fetching: {url}")
            h, s, u = self.fetch_headers(url)
            if h:
                headers, status, used_url = h, s, u
                break

        if not headers:
            error(f"Could not fetch headers from {self.target}")
            results_data["summary"] = "Failed to retrieve HTTP headers"
            return results_data

        success(f"Response: HTTP {status} from {used_url}")
        print()

        print(f"  {C.PURPLE}── All Response Headers ──{C.RESET}")
        for key, val in sorted(headers.items()):
            color = C.CYAN if key.lower() in [h.lower() for h in SECURITY_HEADERS] else C.MUTED
            print(f"  {color}{key:<35}{C.RESET} {val[:80]}")
            results_data["headers"][key] = val

        print(f"\n  {C.PURPLE}── Security Header Audit ──{C.RESET}")
        missing_count = 0
        for header, info_data in SECURITY_HEADERS.items():
            found = any(h.lower() == header.lower() for h in headers)
            if found:
                val = next(v for k, v in headers.items() if k.lower() == header.lower())
                print(f"  {C.GREEN}  [PASS]{C.RESET} {header:<35} {C.MUTED}{val[:50]}{C.RESET}")
            else:
                risk = info_data["risk"]
                risk_color = C.RED if risk == "HIGH" else (C.YELLOW if risk == "MEDIUM" else C.MUTED)
                print(f"  {C.RED}  [MISS]{C.RESET} {header:<35} {risk_color}[{risk}]{C.RESET}")
                finding(info_data["missing_msg"])
                results_data["missing_security"].append(f"[{risk}] Missing: {header} — {info_data['missing_msg']}")
                missing_count += 1

        print(f"\n  {C.PURPLE}── Technology Stack Detection ──{C.RESET}")
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        detected = []
        for sig, tech in TECH_SIGNATURES.items():
            if sig.lower() in header_str.lower():
                print(f"  {C.YELLOW}  [TECH]{C.RESET} {tech}")
                detected.append(tech)
                results_data["tech_stack"].append(tech)

        for h in INTERESTING_HEADERS:
            val = next((v for k, v in headers.items() if k.lower() == h.lower()), None)
            if val:
                print(f"  {C.CYAN}  [INFO]{C.RESET} {h}: {val}")

        if not detected:
            muted("No specific technology signatures detected in headers")

        print()
        success(f"Header audit complete — {missing_count} security header(s) missing")
        results_data["summary"] = f"{missing_count} missing security headers, {len(detected)} tech signatures detected"

        return results_data
