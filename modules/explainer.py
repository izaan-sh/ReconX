"""
ReconX — Plain English Explainer
Converts raw scan findings into beginner-friendly explanations with fix instructions.
"""

# ── Port explanations ────────────────────────────────────────────────────────

PORT_EXPLANATIONS = {
    21: {
        "name": "FTP (File Transfer Protocol)",
        "what": "This port is used to transfer files between computers. It's like a file sharing channel.",
        "risk": "HIGH",
        "why_bad": "FTP sends your username and password as plain readable text — anyone on the same network can intercept and steal your login details.",
        "fix": "Disable FTP entirely if you don't need it. If you do need file transfers, use SFTP (port 22) instead — it encrypts everything.",
        "how_to_fix": "On Linux: run `sudo systemctl stop vsftpd && sudo systemctl disable vsftpd`. On Windows: go to Control Panel → Programs → Turn Windows features on/off → uncheck FTP Server.",
    },
    22: {
        "name": "SSH (Secure Shell)",
        "what": "SSH lets you remotely control a computer through a terminal/command line. It's like a secure remote control.",
        "risk": "MEDIUM",
        "why_bad": "If SSH is open to the internet, attackers may try thousands of username/password combinations automatically (called brute-forcing).",
        "fix": "Make sure you're using strong passwords or better yet, SSH keys (like a digital ID card). Disable password login and only allow key-based login.",
        "how_to_fix": "Edit /etc/ssh/sshd_config: set `PasswordAuthentication no` and `PermitRootLogin no`. Then restart SSH: `sudo systemctl restart ssh`.",
    },
    23: {
        "name": "Telnet",
        "what": "An old way to remotely control computers — like SSH but with zero security.",
        "risk": "CRITICAL",
        "why_bad": "Everything sent over Telnet — including passwords — is completely unencrypted. Anyone watching the network can read it all. This protocol is from the 1960s and should never be used today.",
        "fix": "Disable Telnet immediately and use SSH instead.",
        "how_to_fix": "On Linux: `sudo systemctl stop telnet && sudo systemctl disable telnet`. On network devices, access the admin panel and disable Telnet, enable SSH only.",
    },
    25: {
        "name": "SMTP (Email Sending)",
        "what": "This is how emails get sent from a mail server. Think of it as the post office port.",
        "risk": "MEDIUM",
        "why_bad": "An open SMTP port can be exploited to send spam emails pretending to come from your server, or to relay attacks.",
        "fix": "If you don't run an email server, close this port. If you do, make sure relay is disabled for outside connections.",
        "how_to_fix": "In your email server config (e.g. Postfix), set `smtpd_relay_restrictions = permit_mynetworks, reject`. Block port 25 on your firewall for external access.",
    },
    80: {
        "name": "HTTP (Web Server)",
        "what": "This is the standard port for websites. When you visit a website starting with http://, it uses this port.",
        "risk": "MEDIUM",
        "why_bad": "HTTP is unencrypted — all data between the user and the website can be read by anyone in the middle. Also, outdated web servers have known vulnerabilities.",
        "fix": "Upgrade to HTTPS (port 443) and redirect all HTTP traffic to HTTPS. Keep your web server software updated.",
        "how_to_fix": "On Apache: enable mod_ssl and add a redirect rule. On Nginx: add `return 301 https://$host$request_uri;` in your HTTP server block. Use Let's Encrypt for a free SSL certificate.",
    },
    443: {
        "name": "HTTPS (Secure Web Server)",
        "what": "The secure version of HTTP — this is what you see when a website has a padlock icon.",
        "risk": "LOW",
        "why_bad": "Generally safe, but outdated SSL/TLS versions or weak certificates can still be exploited.",
        "fix": "Ensure you're using TLS 1.2 or 1.3. Disable old versions (SSLv3, TLS 1.0, 1.1). Renew certificates before they expire.",
        "how_to_fix": "In your web server config, set `ssl_protocols TLSv1.2 TLSv1.3;` and disable older protocols. Run SSL Labs test at ssllabs.com/ssltest for a full check.",
    },
    445: {
        "name": "SMB (Windows File Sharing)",
        "what": "SMB is how Windows computers share files and printers with each other on a network.",
        "risk": "CRITICAL",
        "why_bad": "SMB has had some of the most devastating vulnerabilities in history — including EternalBlue, which was used in the WannaCry ransomware attack that affected hundreds of thousands of computers worldwide.",
        "fix": "Never expose SMB to the internet. Apply all Windows security updates immediately. If you don't use file sharing, disable it.",
        "how_to_fix": "Block port 445 on your firewall. On Windows: Control Panel → Network → Advanced Sharing Settings → Turn off file and printer sharing. Ensure KB4012212 and later patches are installed.",
    },
    3306: {
        "name": "MySQL Database",
        "what": "MySQL is a database — it stores data for websites and applications (like user accounts, posts, etc.).",
        "risk": "CRITICAL",
        "why_bad": "A database should never be directly exposed to the internet. If an attacker gets in, they can steal, delete, or modify all your data.",
        "fix": "MySQL should only listen on localhost (127.0.0.1), not on all interfaces. Use a firewall to block external access.",
        "how_to_fix": "In /etc/mysql/mysql.conf.d/mysqld.cnf, set `bind-address = 127.0.0.1`. Restart MySQL: `sudo systemctl restart mysql`.",
    },
    3389: {
        "name": "RDP (Remote Desktop)",
        "what": "RDP lets you see and control another Windows computer's desktop remotely — like TeamViewer but built into Windows.",
        "risk": "CRITICAL",
        "why_bad": "RDP exposed to the internet is one of the top ways attackers break into systems. There have been many critical vulnerabilities (BlueKeep, DejaBlue) and it's heavily targeted by automated attacks.",
        "fix": "Never expose RDP directly to the internet. Use a VPN first, then RDP. Enable Network Level Authentication.",
        "how_to_fix": "Block port 3389 on your router/firewall. Set up a VPN (like WireGuard or OpenVPN) and only allow RDP through the VPN. In Windows: System Properties → Remote → check 'Allow connections only from computers running Remote Desktop with NLA'.",
    },
    5900: {
        "name": "VNC (Remote Desktop)",
        "what": "VNC is another remote desktop tool — it lets you see and control a computer's screen from anywhere.",
        "risk": "CRITICAL",
        "why_bad": "VNC is often set up with weak passwords or no passwords at all. It's commonly exploited by attackers scanning the internet.",
        "fix": "Disable VNC if you don't need it. If you do, use a very strong password and only allow access through a VPN.",
        "how_to_fix": "Stop VNC: `sudo systemctl stop vncserver`. If you need it, run it only on localhost: `vncserver -localhost`. Use an SSH tunnel to connect securely.",
    },
    6379: {
        "name": "Redis (Database Cache)",
        "what": "Redis is a fast in-memory database used by many web applications to store temporary data.",
        "risk": "CRITICAL",
        "why_bad": "By default Redis has NO password protection. If exposed to the internet, attackers can read all stored data, write malicious data, or even take over the server.",
        "fix": "Add a strong password to Redis and bind it to localhost only.",
        "how_to_fix": "In /etc/redis/redis.conf: set `bind 127.0.0.1` and `requirepass YourStrongPasswordHere`. Restart: `sudo systemctl restart redis`.",
    },
    27017: {
        "name": "MongoDB (Database)",
        "what": "MongoDB is a database that stores data for web applications — similar to MySQL but for a different type of data.",
        "risk": "CRITICAL",
        "why_bad": "Old versions of MongoDB had no authentication by default, leading to millions of exposed databases. Even today it's frequently misconfigured.",
        "fix": "Enable authentication and bind to localhost only.",
        "how_to_fix": "In /etc/mongod.conf: set `bindIp: 127.0.0.1` under net section. Enable security: `security: authorization: enabled`. Restart: `sudo systemctl restart mongod`.",
    },
}

# ── HTTP Header explanations ─────────────────────────────────────────────────

HEADER_EXPLANATIONS = {
    "Strict-Transport-Security": {
        "what": "This tells browsers to ALWAYS use the secure (HTTPS) version of your site, even if someone types http://.",
        "why_bad": "Without it, attackers can trick users into using the unencrypted version of your site and intercept everything.",
        "fix": "Add this line to your web server config.",
        "how_to_fix": 'In Apache/Nginx config, add: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`',
    },
    "Content-Security-Policy": {
        "what": "This tells browsers which scripts, images, and resources are allowed to load on your site.",
        "why_bad": "Without it, attackers can inject malicious scripts into your pages (called XSS attacks) that steal user data.",
        "fix": "Define a Content Security Policy that restricts what can run on your site.",
        "how_to_fix": 'Start with: `Content-Security-Policy: default-src \'self\'` in your server config. Use https://csp-evaluator.withgoogle.com to test it.',
    },
    "X-Frame-Options": {
        "what": "This prevents your website from being embedded inside another website's frame/iframe.",
        "why_bad": "Without it, attackers can put your site inside a fake page and trick users into clicking things they didn't intend to (called clickjacking).",
        "fix": "Add the X-Frame-Options header to deny framing.",
        "how_to_fix": 'Add to server config: `Header always set X-Frame-Options "SAMEORIGIN"`',
    },
    "X-Content-Type-Options": {
        "what": "This stops browsers from guessing what type of file is being served.",
        "why_bad": "Without it, a browser might run a file as a script even if it's not supposed to be one — opening the door for attacks.",
        "fix": "Easy one-liner fix in your server config.",
        "how_to_fix": 'Add: `Header always set X-Content-Type-Options "nosniff"` to your Apache/Nginx config.',
    },
    "Referrer-Policy": {
        "what": "Controls how much information your site shares with other sites when someone clicks a link away from yours.",
        "why_bad": "Without it, your full page URL (which might contain sensitive info like user IDs) gets shared with every external site your users visit.",
        "fix": "Set a restrictive referrer policy.",
        "how_to_fix": 'Add: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`',
    },
}

# ── CVE severity explanations ─────────────────────────────────────────────────

SEVERITY_EXPLANATIONS = {
    "CRITICAL": {
        "label": "Critical — Fix Immediately",
        "color": "red",
        "what": "This is as bad as it gets. A critical vulnerability means an attacker can likely take full control of the system, steal all data, or cause complete system failure — often without needing a username or password.",
        "urgency": "Patch or mitigate within 24 hours.",
    },
    "HIGH": {
        "label": "High — Fix Urgently",
        "color": "orange",
        "what": "A serious vulnerability. An attacker with basic skill could exploit this to gain significant access, steal data, or disrupt services.",
        "urgency": "Patch within 1 week.",
    },
    "MEDIUM": {
        "label": "Medium — Fix Soon",
        "color": "yellow",
        "what": "A real issue, but harder to exploit — usually requires the attacker to already have some access, or depends on specific conditions.",
        "urgency": "Patch within 30 days.",
    },
    "LOW": {
        "label": "Low — Fix When Possible",
        "color": "blue",
        "what": "Minor issue with limited impact on its own. Could contribute to a bigger attack if combined with other vulnerabilities.",
        "urgency": "Address in your next maintenance window.",
    },
}


def explain_findings(results):
    """
    Takes raw scan results and produces a list of beginner-friendly
    finding objects sorted by severity.
    """
    findings = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    # Port findings
    if "ports" in results:
        ports_data = results["ports"]
        for port_info in ports_data.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "Unknown")
            banner = port_info.get("banner", "")
            exp = PORT_EXPLANATIONS.get(port)

            if exp:
                findings.append({
                    "id": f"port_{port}",
                    "category": "Open Port",
                    "title": f"Port {port} is open — {exp['name']}",
                    "what_is_it": exp["what"],
                    "risk": exp["risk"],
                    "why_is_it_a_problem": exp["why_bad"],
                    "how_to_fix": exp["fix"],
                    "technical_fix": exp["how_to_fix"],
                    "details": f"Banner: {banner}" if banner else f"Service: {service}",
                })
            else:
                findings.append({
                    "id": f"port_{port}",
                    "category": "Open Port",
                    "title": f"Port {port} is open — {service}",
                    "what_is_it": f"Port {port} is open and running {service}. Open ports are entry points into a system.",
                    "risk": "MEDIUM",
                    "why_is_it_a_problem": "Every open port is a potential entry point for attackers. If the service running on this port has vulnerabilities or weak configuration, it could be exploited.",
                    "how_to_fix": "If you don't need this service, disable it and close the port.",
                    "technical_fix": f"Identify what's using port {port} with `ss -tlnp | grep {port}` and disable if not needed.",
                    "details": f"Banner: {banner}" if banner else f"Service: {service}",
                })

    # HTTP Header findings
    if "headers" in results:
        headers_data = results["headers"]
        for missing in headers_data.get("missing_security", []):
            # Parse the missing header name from the string
            header_name = missing.replace("[HIGH] Missing: ", "").replace("[MEDIUM] Missing: ", "").replace("[LOW] Missing: ", "").split(" —")[0].strip()
            risk = "HIGH" if "[HIGH]" in missing else ("MEDIUM" if "[MEDIUM]" in missing else "LOW")
            exp = HEADER_EXPLANATIONS.get(header_name, {})
            findings.append({
                "id": f"header_{header_name.lower().replace('-','_')}",
                "category": "Missing Security Header",
                "title": f"Missing security header: {header_name}",
                "what_is_it": exp.get("what", f"The {header_name} security header is not set on this web server."),
                "risk": risk,
                "why_is_it_a_problem": exp.get("why_bad", "Missing security headers leave your website open to certain types of attacks."),
                "how_to_fix": exp.get("fix", "Add this header to your web server configuration."),
                "technical_fix": exp.get("how_to_fix", f"Add the {header_name} header to your Apache/Nginx server configuration."),
                "details": "",
            })

        # Tech stack info
        for tech in headers_data.get("tech_stack", []):
            findings.append({
                "id": f"tech_{tech.lower().replace(' ','_')}",
                "category": "Technology Disclosure",
                "title": f"Server is revealing it uses: {tech}",
                "what_is_it": "The web server is advertising which software it's running in its response headers.",
                "risk": "LOW",
                "why_is_it_a_problem": "Knowing the exact software and version helps attackers look up known vulnerabilities for that specific version.",
                "how_to_fix": "Hide or remove version information from server response headers.",
                "technical_fix": "In Apache: set `ServerTokens Prod` and `ServerSignature Off`. In Nginx: set `server_tokens off`.",
                "details": f"Detected: {tech}",
            })

    # CVE findings
    if "cve" in results:
        cve_data = results["cve"]
        for cve in cve_data.get("cves", []):
            sev = cve.get("severity", "MEDIUM")
            sev_exp = SEVERITY_EXPLANATIONS.get(sev, SEVERITY_EXPLANATIONS["MEDIUM"])
            if sev in ("CRITICAL", "HIGH"):
                findings.append({
                    "id": cve["id"],
                    "category": "Known Vulnerability (CVE)",
                    "title": f"{cve['id']} — CVSS Score: {cve['score']}",
                    "what_is_it": f"A CVE (Common Vulnerabilities and Exposures) is a publicly known security flaw. {sev_exp['what']}",
                    "risk": sev,
                    "why_is_it_a_problem": cve.get("description", "Known vulnerability with public exploit potential."),
                    "how_to_fix": f"Apply the latest security patches for the affected service. {sev_exp['urgency']}",
                    "technical_fix": f"Check the NVD entry at https://nvd.nist.gov/vuln/detail/{cve['id']} for the official patch/fix. Update the affected software to the latest version.",
                    "details": f"Published: {cve.get('published', 'N/A')}",
                })

    # DNS findings
    if "dns" in results:
        dns_data = results["dns"]
        subs = dns_data.get("subdomains", [])
        if subs:
            findings.append({
                "id": "dns_subdomains",
                "category": "DNS — Subdomains Found",
                "title": f"{len(subs)} subdomain(s) discovered",
                "what_is_it": "Subdomains are separate sections of a website (like api.example.com, admin.example.com). Each one is a separate potential entry point.",
                "risk": "MEDIUM",
                "why_is_it_a_problem": "Forgotten or old subdomains (like dev.example.com or staging.example.com) are often left with weaker security than the main site.",
                "how_to_fix": "Review each subdomain and make sure they are all intentional and properly secured.",
                "technical_fix": "For each subdomain found, check if it's still needed. Remove DNS records for decommissioned services.",
                "details": ", ".join(s["subdomain"] for s in subs[:5]),
            })

    # WHOIS findings
    if "whois" in results:
        whois_data = results["whois"]
        for f in whois_data.get("findings", []):
            if "expires" in f.lower():
                findings.append({
                    "id": "whois_expiry",
                    "category": "Domain Registration",
                    "title": "Domain expiring soon",
                    "what_is_it": "Your domain registration is close to its expiry date.",
                    "risk": "HIGH",
                    "why_is_it_a_problem": "If your domain expires, attackers can register it and impersonate your website, stealing all your traffic and potentially your users' data.",
                    "how_to_fix": "Renew your domain immediately and set it to auto-renew.",
                    "technical_fix": "Log in to your domain registrar and renew the domain. Enable auto-renewal. Set up expiry alert emails.",
                    "details": f,
                })

    # Sort by severity
    findings.sort(key=lambda x: severity_order.get(x["risk"], 99))
    return findings
