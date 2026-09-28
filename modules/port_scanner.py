"""
ReconX — Port Scanner Module
Performs TCP port scanning with banner grabbing and service detection.
"""

import socket
import concurrent.futures
import time
from modules.banner import info, success, warn, error, muted, finding, data, section_header, Colors as C

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    27017: "MongoDB",
}

RISKY_PORTS = {
    21: "FTP often transmits credentials in plaintext",
    23: "Telnet is unencrypted — replace with SSH",
    3389: "RDP exposed to internet is high-value target",
    445: "SMB — check for EternalBlue / MS17-010",
    1433: "MSSQL exposed — brute-force risk",
    5900: "VNC exposed — often weak auth",
    6379: "Redis with no auth — critical data exposure risk",
    27017: "MongoDB with no auth — critical data exposure risk",
}


class PortScanner:
    def __init__(self, target, ports=None, timeout=1.0, threads=100):
        self.target = target
        self.ports = ports or list(COMMON_PORTS.keys())
        self.timeout = timeout
        self.threads = threads
        self.results = []

    def resolve_target(self):
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            return None

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self._grab_banner(sock, port)
                sock.close()
                return (port, True, banner)
            sock.close()
            return (port, False, "")
        except Exception:
            return (port, False, "")

    def _grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            if port in (80, 8080, 8888, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 22:
                pass
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:120] if banner else ""
        except Exception:
            return ""

    def run(self):
        section_header("PORT SCANNER")
        results_data = {"open_ports": [], "findings": [], "summary": ""}

        ip = self.resolve_target()
        if not ip:
            error(f"Could not resolve hostname: {self.target}")
            results_data["summary"] = f"DNS resolution failed for {self.target}"
            return results_data

        if ip != self.target:
            info(f"Resolved {self.target} → {ip}")

        info(f"Scanning {len(self.ports)} ports on {ip} with {self.threads} threads...")
        muted("This may take a moment...")
        print()

        open_ports = []
        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))

        elapsed = round(time.time() - start, 2)
        open_ports.sort(key=lambda x: x[0])

        if not open_ports:
            warn("No open ports found on common ports.")
            results_data["summary"] = f"No open ports found. Scan completed in {elapsed}s."
            return results_data

        print(f"  {'PORT':<10} {'SERVICE':<14} {'STATE':<10} BANNER / INFO")
        print(f"  {'─'*10} {'─'*14} {'─'*10} {'─'*30}")

        for port, banner in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            state = f"{C.GREEN}open{C.RESET}"
            banner_short = banner.split("\n")[0][:60] if banner else ""
            print(f"  {C.CYAN}{port:<10}{C.RESET} {service:<14} {state:<20} {C.MUTED}{banner_short}{C.RESET}")

            port_info = {"port": port, "service": service, "banner": banner_short}
            results_data["open_ports"].append(port_info)

            if port in RISKY_PORTS:
                risk_msg = f"Port {port}/{service} — {RISKY_PORTS[port]}"
                finding(risk_msg)
                results_data["findings"].append(risk_msg)

        print()
        success(f"Scan complete — {len(open_ports)} open port(s) found in {elapsed}s")
        results_data["summary"] = f"{len(open_ports)} open ports found in {elapsed}s on {ip}"

        return results_data
