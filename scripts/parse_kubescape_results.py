#!/usr/bin/env python3
"""
parse_kubescape_results.py
 Parse Kubescape HTML reports and generate a consolidated summary HTML.

Usage:
  python3 parse_kubescape_results.py \
      --host master1 \
      --full /path/to/kubescape-full-scan.html \
      --nsa /path/to/kubescape-nsa.html \
      --mitre /path/to/kubescape-mitre.html \
      --output /path/to/kubescape-summary.html
"""

import argparse
import re
from pathlib import Path
from html.parser import HTMLParser
from datetime import datetime

# Strip class attributes to make parsing simpler
RE_TR = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S)
RE_TD = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
RE_TH = re.compile(r"<th[^>]*>(.*?)</th>", re.S)
RE_TAG = re.compile(r"<[^>]+>")
RE_NBSP = re.compile(r"&nbsp;|&#160;")

def strip_tags(html_fragment):
    """Remove HTML tags from a string."""
    t = RE_TAG.sub("", html_fragment)
    t = RE_NBSP.sub(" ", t)
    return t.strip()

def extract_summary_table(content):
    """Extract Summary table: All, Failed, Skipped counts."""
    # Find the summary table
    m = re.search(r"<h2>Summary:</h2>.*?<table[^>]*>.*?</table>", content, re.S)
    if not m:
        return None
    table = m.group(0)
    rows = RE_TR.findall(table)
    if len(rows) < 2:
        return None
    # rows[0] = header, rows[1] = data
    headers = [strip_tags(h) for h in RE_TH.findall(rows[0])]
    data = [strip_tags(d) for d in RE_TD.findall(rows[1])]
    result = {}
    for h, d in zip(headers, data):
        result[h] = d
    return result

def extract_control_rows(content, max_rows=50):
    """Extract control rows from the Details table."""
    # Find the Details table
    m = re.search(r"<h2>Details</h2>.*?<table[^>]*>(.*?)</table>", content, re.S)
    if not m:
        return []

    table_body = m.group(1)
    rows = RE_TR.findall(table_body)
    if not rows:
        return []

    # First row might be header inside thead
    controls = []
    for row in rows:
        tds = RE_TD.findall(row)
        if len(tds) < 3:
            continue
        # Typical structure: severity, control_name, failed_resources, all_resources, risk_score
        # Depending on exact HTML, there might be 4-5 columns
        severity = strip_tags(tds[0])
        name = strip_tags(tds[1])
        failed = strip_tags(tds[2]) if len(tds) > 2 else ""
        all_res = strip_tags(tds[3]) if len(tds) > 3 else ""
        risk = strip_tags(tds[4]) if len(tds) > 4 else ""

        if severity and severity.lower() in ("critical", "high", "medium", "low", "unknown"):
            controls.append({
                "severity": severity,
                "name": name,
                "failed": failed,
                "all": all_res,
                "risk": risk,
            })

    # Sort by severity weight
    sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    controls.sort(key=lambda x: sev_weight.get(x["severity"].lower(), 5))
    return controls[:max_rows]

def parse_kubescape_report(path):
    """Parse a single kubescape HTML report."""
    if not path or not Path(path).exists():
        return None
    content = Path(path).read_text(encoding="utf-8")
    summary = extract_summary_table(content)
    controls = extract_control_rows(content)
    return {"summary": summary, "controls": controls}

def severity_class(severity):
    s = severity.lower()
    if s == "critical":
        return "red"
    elif s == "high":
        return "orange"
    elif s == "medium":
        return "yellow"
    elif s == "low":
        return "green"
    return ""

def generate_html(hostname, full_data, nsa_data, mitre_data, report_paths, output_file):
    """Generate consolidated Kubescape summary HTML."""

    # Build summary cards
    cards = ""
    defs = [
        ("Full Scan", full_data, report_paths.get("full")),
        ("NSA/CISA", nsa_data, report_paths.get("nsa")),
        ("MITRE ATT&CK", mitre_data, report_paths.get("mitre")),
    ]
    for name, data, rpath in defs:
        if not data or not data.get("summary"):
            cards += f"""
            <div class="card">
              <div class="metric">N/A</div>
              <div class="label">{name}</div>
              <div class="badge">No data</div>
            </div>"""
            continue
        s = data["summary"]
        all_c = s.get("All", "0")
        failed = s.get("Failed", "0")
        skipped = s.get("Skipped", "0")
        try:
            pct = round((int(failed) / int(all_c)) * 100, 1) if int(all_c) > 0 else 0
        except ValueError:
            pct = 0

        risk_class = "green"
        risk_label = "LOW"
        try:
            fval = int(failed)
            if fval > 30:
                risk_class = "red"; risk_label = "CRITICAL"
            elif fval > 20:
                risk_class = "orange"; risk_label = "HIGH"
            elif fval > 10:
                risk_class = "yellow"; risk_label = "MEDIUM"
        except ValueError:
            pass

        cards += f"""
        <div class="card">
          <div class="metric {risk_class}">{failed}/{all_c}</div>
          <div class="label">{name} Failed Controls</div>
          <div class="badge badge-{risk_class}">{risk_label} RISK</div>
          <div style="font-size:0.8rem; margin-top:0.5rem; color:#aaa;">Skipped: {skipped}</div>
          <div style="margin-top:0.75rem;"><a class="btn" href="{rpath or '#'}" target="_blank">View Full Report</a></div>
        </div>"""

    # Build top issues table (combine all controls, dedup by name, take top)
    all_controls = []
    seen = set()
    for data in (full_data, nsa_data, mitre_data):
        if not data:
            continue
        for c in data.get("controls", []):
            key = c["name"]
            if key not in seen:
                seen.add(key)
                all_controls.append(c)

    # Sort by severity
    sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    all_controls.sort(key=lambda x: sev_weight.get(x["severity"].lower(), 5))
    top_controls = all_controls[:40]

    rows = ""
    for c in top_controls:
        sc = severity_class(c["severity"])
        rows += f"""
        <tr>
          <td><span class="badge badge-{sc}">{c['severity'].upper()}</span></td>
          <td>{c['name']}</td>
          <td>{c.get('failed', '')}</td>
          <td>{c.get('all', '')}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="4">No control data available</td></tr>'

    # Recommendations
    recommendations = """
    <ul class="recommendations">
      <li><strong>Enable RBAC audit logging:</strong> Configure the API server with <code>--audit-log-path</code> and <code>--audit-policy-file</code> to capture authorization decisions</li>
      <li><strong>Remove anonymous access:</strong> Disable anonymous authentication on the API server (<code>--anonymous-auth=false</code>) or bind anonymous to a restricted RBAC role</li>
      <li><strong>Enable etcd encryption:</strong> Configure etcd encryption at rest using <code>aescbc</code> or <code>secretbox</code>; add <code>EncryptionConfiguration</code> to API server</li>
      <li><strong>Restrict privileged containers:</strong> Use Pod Security Standards (Restricted) or OPA/Gatekeeper to prevent pods from running as privileged</li>
      <li><strong>Remove hostPath volumes:</strong> Audit workloads for unnecessary <code>hostPath</code> mounts; replace with PVCs or emptyDir where possible</li>
      <li><strong>Apply least-privilege RBAC:</strong> Replace cluster-admin bindings with namespace-scoped roles; audit service accounts for excessive permissions</li>
      <li><strong>Enable Pod Security Admission:</strong> Enforce the <code>restricted</code> Pod Security Standard cluster-wide</li>
      <li><strong>Rotate kubeconfig tokens:</strong> Regularly rotate service account tokens and ensure short-lived tokens are used where possible</li>
      <li><strong>Network policies:</strong> Apply default-deny network policies in all namespaces and explicitly allow required traffic</li>
      <li><strong>Scan container images:</strong> Integrate Trivy or Clair into CI/CD to catch CVEs before deployment</li>
    </ul>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Kubescape Security Summary - {hostname}</title>
<style>
  :root {{
    --bg: #1a1a2e;
    --card: #16213e;
    --text: #e0e0e0;
    --accent: #0f3460;
    --green: #00d26a;
    --red: #e94560;
    --orange: #f39c12;
    --yellow: #f1c40f;
    --blue: #3498db;
  }}
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2rem;
    max-width: 80rem;
    margin: 0 auto;
  }}
  h1, h2, h3 {{
    color: #fff;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 0.5rem;
  }}
  .header {{
    background: var(--card);
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .header-info {{
    font-size: 0.9rem;
    color: #aaa;
  }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
  }}
  .card {{
    background: var(--card);
    padding: 1.5rem;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  }}
  .metric {{
    font-size: 2.2rem;
    font-weight: bold;
    color: var(--blue);
  }}
  .metric.green {{ color: var(--green); }}
  .metric.red {{ color: var(--red); }}
  .metric.orange {{ color: var(--orange); }}
  .metric.yellow {{ color: var(--yellow); }}
  .label {{
    font-size: 0.85rem;
    color: #aaa;
    margin-top: 0.5rem;
  }}
  .badge {{
    display: inline-block;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: bold;
    text-transform: uppercase;
  }}
  .badge-green {{ background: var(--green); color: #000; }}
  .badge-red {{ background: var(--red); color: #fff; }}
  .badge-orange {{ background: var(--orange); color: #000; }}
  .badge-yellow {{ background: var(--yellow); color: #000; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    background: var(--card);
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--accent);
  }}
  th {{
    background: var(--accent);
    color: #fff;
    font-weight: 600;
  }}
  tr:hover {{ background: rgba(255,255,255,0.03); }}
  .recommendations {{
    background: var(--card);
    padding: 1.5rem 2rem;
    border-radius: 8px;
    line-height: 1.8;
  }}
  .recommendations li {{
    margin-bottom: 0.5rem;
  }}
  code {{
    background: #2a2a4a;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    font-family: monospace;
  }}
  .btn {{
    display: inline-block;
    background: var(--accent);
    color: #fff;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    text-decoration: none;
    font-size: 0.85rem;
  }}
  .btn:hover {{ background: var(--blue); }}
  .report-iframe {{
    width: 100%;
    height: 600px;
    border: 1px solid var(--accent);
    border-radius: 8px;
    margin-top: 1rem;
  }}
  .tabs {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }}
  .tab {{
    background: var(--card);
    border: none;
    color: var(--text);
    padding: 0.5rem 1rem;
    border-radius: 4px;
    cursor: pointer;
  }}
  .tab.active {{
    background: var(--blue);
    color: #fff;
  }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>Kubescape Security Summary</h1>
      <div class="header-info">Host: <strong>{hostname}</strong> | Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
  </div>

  <h2>Scan Results Overview</h2>
  <div class="summary-grid">
    {cards}
  </div>

  <h2>Top Failed Controls (Across All Frameworks)</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Control Name</th>
        <th>Failed Resources</th>
        <th>All Resources</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <h2>Detailed Reports</h2>
  <div class="tabs">
    <button class="tab active" onclick="showTab('tab-full')">Full Scan</button>
    <button class="tab" onclick="showTab('tab-nsa')">NSA/CISA</button>
    <button class="tab" onclick="showTab('tab-mitre')">MITRE ATT&CK</button>
  </div>

  <div id="tab-full" class="tab-content active">
    {"<iframe class='report-iframe' src='" + (report_paths.get('full') or '') + "'></iframe>" if report_paths.get('full') else '<p>Full scan report not available.</p>'}
  </div>
  <div id="tab-mitre" class="tab-content">
    {"<iframe class='report-iframe' src='" + (report_paths.get('mitre') or '') + "'></iframe>" if report_paths.get('mitre') else '<p>MITRE scan report not available.</p>'}
  </div>
  <div id="tab-nsa" class="tab-content">
    {"<iframe class='report-iframe' src='" + (report_paths.get('nsa') or '') + "'></iframe>" if report_paths.get('nsa') else '<p>NSA scan report not available.</p>'}
  </div>

  <h2>Recommendations</h2>
  {recommendations}

  <footer style="text-align:center; color:#666; margin-top:3rem; font-size:0.8rem;">
    Generated by Kubescape Reporter | Ansible + k8s-security-reporting skill
  </footer>

  <script>
    function showTab(id) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
      document.getElementById(id).classList.add('active');
      event.target.classList.add('active');
    }}
  </script>
</body>
</html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"Generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Parse Kubescape HTML reports and generate summary")
    parser.add_argument("--host", required=True, help="Target hostname")
    parser.add_argument("--full", required=True, help="Path to full scan HTML")
    parser.add_argument("--nsa", required=True, help="Path to NSA scan HTML")
    parser.add_argument("--mitre", required=True, help="Path to MITRE scan HTML")
    parser.add_argument("--output", required=True, help="Output HTML file path")
    args = parser.parse_args()

    full_data = parse_kubescape_report(args.full)
    nsa_data = parse_kubescape_report(args.nsa)
    mitre_data = parse_kubescape_report(args.mitre)

    paths = {
        "full": args.full,
        "nsa": args.nsa,
        "mitre": args.mitre,
    }

    generate_html(args.host, full_data, nsa_data, mitre_data, paths, args.output)

if __name__ == "__main__":
    main()
