"""
ReconX — Report Generator
Saves .txt and .html reports named by scan name or target.
"""

import os
import json
import re
from datetime import datetime


class ReportGenerator:
    def __init__(self, target, scan_name=None):
        self.target = target
        self.scan_name = scan_name or target
        self.sections = []
        self.start_time = datetime.now()

    def has_content(self):
        return len(self.sections) > 0

    def add_section(self, name, data):
        self.sections.append({
            "name": name,
            "data": data,
            "time": datetime.now().isoformat()
        })

    def _safe_filename(self, name):
        safe = re.sub(r'[^\w\-_. ]', '_', name)
        return safe.strip().replace(" ", "_")[:50]

    def save(self, output_path=None):
        os.makedirs("reports", exist_ok=True)
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        safe_name = self._safe_filename(self.scan_name)

        if output_path:
            base = output_path.replace(".txt", "").replace(".html", "")
        else:
            base = f"reports/{safe_name}_{timestamp}"

        txt_path = base + ".txt"
        html_path = base + ".html"

        self._save_txt(txt_path)
        self._save_html(html_path)

        return {"txt": txt_path, "html": html_path}

    def _all_findings(self):
        findings = []
        for s in self.sections:
            d = s["data"]
            if isinstance(d, dict):
                findings.extend(d.get("findings", []))
        return findings

    def _save_txt(self, path):
        lines = []
        lines.append("=" * 60)
        lines.append("  RECONX SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"  Scan Name : {self.scan_name}")
        lines.append(f"  Target    : {self.target}")
        lines.append(f"  Date      : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Modules   : {len(self.sections)}")
        lines.append("=" * 60)

        findings = self._all_findings()
        if findings:
            lines.append("\n  FINDINGS")
            lines.append("  " + "-" * 40)
            for f in findings:
                lines.append(f"  [!] {f}")

        for section in self.sections:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"  MODULE: {section['name'].upper()}")
            lines.append(f"{'=' * 60}")
            d = section["data"]
            if isinstance(d, dict):
                lines.append(f"  Summary: {d.get('summary', '')}")
                for key, val in d.items():
                    if key in ("summary", "findings"):
                        continue
                    if isinstance(val, list) and val:
                        lines.append(f"\n  {key.upper()}:")
                        for item in val:
                            lines.append(f"    {json.dumps(item) if isinstance(item, dict) else item}")
                    elif isinstance(val, dict):
                        lines.append(f"\n  {key.upper()}:")
                        for k, v in val.items():
                            lines.append(f"    {k}: {v}")

        lines.append(f"\n{'=' * 60}")
        lines.append("  END OF REPORT — ReconX")
        lines.append(f"{'=' * 60}\n")

        with open(path, "w") as f:
            f.write("\n".join(lines))

    def _save_html(self, path):
        findings = self._all_findings()
        total_cves = sum(len(s["data"].get("cves", [])) for s in self.sections if isinstance(s["data"], dict))
        critical = sum(
            1 for s in self.sections if isinstance(s["data"], dict)
            for c in s["data"].get("cves", []) if c.get("severity") == "CRITICAL"
        )

        findings_html = "".join(
            f'<div class="finding"><span class="tag warn">[!]</span> {f}</div>' for f in findings
        )

        sections_html = "".join(f"""
        <div class="section">
            <h2>{s['name']}</h2>
            <p class="summary">{s['data'].get('summary', '') if isinstance(s['data'], dict) else ''}</p>
            <pre>{json.dumps(s['data'], indent=2)}</pre>
        </div>""" for s in self.sections)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconX Report — {self.scan_name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Courier New', monospace; background: #0a0e13; color: #c9d1d9; padding: 24px; }}
  h1 {{ color: #58a6ff; font-size: 22px; margin-bottom: 4px; }}
  h2 {{ color: #d2a8ff; font-size: 15px; margin: 0 0 8px; }}
  .meta {{ color: #484f58; font-size: 12px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 12px 20px; }}
  .stat-num {{ font-size: 28px; font-weight: 700; color: #58a6ff; }}
  .stat-label {{ font-size: 11px; color: #484f58; margin-top: 2px; }}
  .findings {{ background: #161b22; border: 1px solid #f85149; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
  .finding {{ font-size: 12px; color: #ffa657; padding: 4px 0; border-bottom: 1px solid #21262d; }}
  .tag {{ font-size: 10px; border-radius: 3px; padding: 1px 6px; margin-right: 6px; background: #3d2300; color: #ffa657; }}
  .section {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .summary {{ font-size: 12px; color: #8b949e; margin-bottom: 12px; }}
  pre {{ font-size: 11px; color: #8b949e; overflow-x: auto; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }}
  .footer {{ color: #484f58; font-size: 11px; margin-top: 24px; text-align: center; }}
</style>
</head>
<body>
  <h1>ReconX Scan Report</h1>
  <div class="meta">Scan: {self.scan_name} | Target: {self.target} | Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</div>
  <div class="stats">
    <div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-label">Findings</div></div>
    <div class="stat"><div class="stat-num">{total_cves}</div><div class="stat-label">CVEs</div></div>
    <div class="stat"><div class="stat-num" style="color:#f85149">{critical}</div><div class="stat-label">Critical</div></div>
  </div>
  {"<div class='findings'><h2>Findings</h2>" + findings_html + "</div>" if findings else ""}
  {sections_html}
  <div class="footer">Generated by ReconX | Author: Izaan Shumaiz</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
