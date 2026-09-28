"""
ReconX — Banner & Color Utilities
"""


class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    PURPLE  = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    MUTED   = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

C = Colors


BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{C.RESET}
{C.MUTED}  Automated Recon & Vulnerability Scanner{C.RESET}
{C.MUTED}  Author : Izaan Shumaiz | ICT387 Portfolio{C.RESET}
{C.MUTED}  Version: 1.0{C.RESET}
{C.RED}  [!] Use only on systems you own or have explicit permission to test.{C.RESET}
"""

MENU = f"""
{C.MUTED}  ──────────────────────────────────────────{C.RESET}
{C.WHITE}  {C.CYAN}[1]{C.RESET}  Port Scanner        — TCP port enumeration & banner grab
{C.WHITE}  {C.CYAN}[2]{C.RESET}  HTTP Headers        — Security header analysis
{C.WHITE}  {C.CYAN}[3]{C.RESET}  DNS Enumeration     — A/MX/NS/TXT records + subdomain hints
{C.WHITE}  {C.CYAN}[4]{C.RESET}  CVE Lookup          — Search NVD for known vulnerabilities
{C.WHITE}  {C.CYAN}[5]{C.RESET}  WHOIS Info          — Domain registration data
{C.PURPLE}  [6]{C.RESET}  Full Scan           — Run all modules sequentially
{C.YELLOW}  [7]{C.RESET}  Export Report       — Save findings to file
{C.MUTED}  [0]{C.RESET}  Exit
{C.MUTED}  ──────────────────────────────────────────{C.RESET}"""


def print_banner():
    print(BANNER)


def print_menu():
    print(MENU)


def section_header(title):
    width = 50
    pad = (width - len(title) - 2) // 2
    line = "─" * width
    print(f"\n{C.PURPLE}  ┌{line}┐{C.RESET}")
    print(f"{C.PURPLE}  │{' ' * pad} {title} {' ' * pad}│{C.RESET}")
    print(f"{C.PURPLE}  └{line}┘{C.RESET}\n")


def info(msg):    print(f"{C.BLUE}  [*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}  [✓]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}  [!]{C.RESET} {msg}")
def error(msg):   print(f"{C.RED}  [✗]{C.RESET} {msg}")
def muted(msg):   print(f"{C.MUTED}  [~] {msg}{C.RESET}")
def finding(msg): print(f"{C.RED}  [FINDING]{C.RESET} {msg}")
def data(label, value): print(f"  {C.CYAN}{label:<20}{C.RESET} {value}")
