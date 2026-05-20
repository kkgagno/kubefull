#!/usr/bin/env python3
"""
parse_openscap_results.py
 Parse OpenSCAP XCCDF results XML and generate an HTML summary report.

Usage:
  python3 parse_openscap_results.py \
      --input /path/to/compliance-results.xml \
      --vuln /path/to/vulnerability-results.xml \
      --hostname master1 \
      --output /path/to/openscap-summary.html
"""

import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

def parse_xccdf(xml_file):
    """Parse XCCDF results and return structured data."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

    # Namespace prefix may vary; try with and without
    test_result = root.find(".//xccdf:TestResult", ns)
    if test_result is None:
        test_result = root.find(".//{http://checklists.nist.gov/xccdf/1.2}TestResult")
    if test_result is None:
        test_result = root.find(".//TestResult")

    if test_result is None:
        return None, f"No TestResult found in {xml_file}"

    # Overall score
    score_el = test_result.find("xccdf:score", ns)
    if score_el is None:
        score_el = test_result.find(".//{http://checklists.nist.gov/xccdf/1.2}score")
    if score_el is None:
        score_el = test_result.find(".//score")
    score = float(score_el.text) if score_el is not None and score_el.text else 0.0
    score_max = float(score_el.get("maximum", "100")) if score_el is not None else 100.0

    # Profile
    profile = test_result.get("id", "unknown")
    if "profile" in profile:
        profile = profile.split("_profile_")[-1]

    # Rule results
    results = {"pass": 0, "fail": 0, "error": 0, "notchecked": 0, "notapplicable": 0, "unknown": 0, "fixed": 0}
    failed_rules = []

    rule_results = test_result.findall("xccdf:rule-result", ns)
    if not rule_results:
        rule_results = test_result.findall(".//{http://checklists.nist.gov/xccdf/1.2}rule-result")
    if not rule_results:
        rule_results = test_result.findall(".//rule-result")

    for rr in rule_results:
        res_el = rr.find("xccdf:result", ns)
        if res_el is None:
            res_el = rr.find("result")
        result_text = (res_el.text or "").lower().strip() if res_el is not None else "unknown"

        rule_id = rr.get("idref", "unknown")
        if "_rule_" in rule_id:
            rule_name = rule_id.split("_rule_")[-1]
        else:
            rule_name = rule_id

        if result_text in results:
            results[result_text] += 1
        else:
            results["unknown"] += 1

        if result_text in ("fail", "error"):
            failed_rules.append({"id": rule_id, "name": rule_name, "result": result_text})

    total = sum(results.values())
    compliance_pct = round((results["pass"] / total * 100), 1) if total > 0 else 0.0

    return {
        "score": score,
        "score_max": score_max,
        "profile": profile,
        "total_rules": total,
        "results": results,
        "compliance_pct": compliance_pct,
        "failed_rules": failed_rules,
        "timestamp": datetime.now().isoformat(),
    }, None

def parse_oval(xml_file):
    """Parse OVAL results and return vulnerability count."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-results-5"}

        definitions = root.findall(".//oval:definition", ns)
        if not definitions:
            definitions = root.findall(".//{http://oval.mitre.org/XMLSchema/oval-results-5}definition")
        if not definitions:
            definitions = root.findall(".//definition")

        total = 0
        true_positive = 0
        false_positive = 0
        unknown = 0

        for d in definitions:
            result = d.get("result", "").lower()
            total += 1
            if result == "true":
                true_positive += 1
            elif result == "false":
                false_positive += 1
            else:
                unknown += 1

        return {
            "total_definitions": total,
            "vulnerable": true_positive,
            "not_vulnerable": false_positive,
            "unknown": unknown,
        }, None
    except Exception as e:
        return None, str(e)

def generate_html(hostname, compliance_data, vuln_data, output_file):
    """Generate HTML summary report."""
    c = compliance_data or {}
    v = vuln_data or {}

    compliance_html = ""
    if c:
        total = c.get("total_rules", 0)
        results = c.get("results", {})
        pass_count = results.get("pass", 0)
        fail_count = results.get("fail", 0)
        error_count = results.get("error", 0)
        notchecked = results.get("notchecked", 0)
        compliance_pct = c.get("compliance_pct", 0)
        score = c.get("score", 0)
        profile = c.get("profile", "unknown")

        failed_rules = c.get("failed_rules", [])
        failed_rows = ""
        for fr in failed_rules[:50]:  # Top 50
            failed_rows += f"""
            <tr>
              <td>{fr['name']}</td>
              <td><span class="badge badge-fail">{fr['result'].upper()}</span></td>
            </tr>
            """
        if len(failed_rules) > 50:
            failed_rows += f"<tr><td colspan=\"2\"><em>...and {len(failed_rules) - 50} more failures</em></td></tr>"

        compliance_html = f"""
        <h2>Compliance Scan (CIS Level 1 Server)</h2>
        <div class="summary-grid">
          <div class="card">
            <div class="metric">{compliance_pct}%</div>
            <div class="label">Compliance Rate</div>
            <div class="bar-container"><div class="bar bar-green" style="width:{compliance_pct}%"></div></div>
          </div>
          <div class="card">
            <div class="metric">{score:.1f}</div>
            <div class="label">Score (max {c.get('score_max', 100)})</div>
          </div>
          <div class="card">
            <div class="metric">{total}</div>
            <div class="label">Total Rules</div>
          </div>
          <div class="card">
            <div class="metric green">{pass_count}</div>
            <div class="label">Passed</div>
          </div>
          <div class="card">
            <div class="metric red">{fail_count}</div>
            <div class="label">Failed</div>
          </div>
          <div class="card">
            <div class="metric orange">{error_count}</div>
            <div class="label">Errors</div>
          </div>
        </div>

        <h3>Failed Rules ({len(failed_rules)})</h3>
        <table>
          <thead><tr><th>Rule</th><th>Result</th></tr></thead>
          <tbody>{failed_rows}</tbody>
        </table>
        """

    vuln_html = ""
    if v:
        total_defs = v.get("total_definitions", 0)
        vuln_count = v.get("vulnerable", 0)
        not_vuln = v.get("not_vulnerable", 0)
        unknown = v.get("unknown", 0)
        risk_pct = round((vuln_count / total_defs * 100), 1) if total_defs > 0 else 0.0

        risk_class = "green"
        risk_label = "LOW"
        if vuln_count > 50:
            risk_class = "red"
            risk_label = "CRITICAL"
        elif vuln_count > 20:
            risk_class = "orange"
            risk_label = "HIGH"
        elif vuln_count > 5:
            risk_class = "yellow"
            risk_label = "MEDIUM"

        vuln_html = f"""
        <h2>Vulnerability Scan (OVAL)</h2>
        <div class="summary-grid">
          <div class="card">
            <div class="metric {risk_class}">{vuln_count}</div>
            <div class="label">Vulnerabilities Found</div>
            <div class="badge badge-{risk_class}">{risk_label} RISK</div>
          </div>
          <div class="card">
            <div class="metric">{total_defs}</div>
            <div class="label">CVEs Checked</div>
          </div>
          <div class="card">
            <div class="metric green">{not_vuln}</div>
            <div class="label">Not Affected</div>
          </div>
          <div class="card">
            <div class="metric">{unknown}</div>
            <div class="label">Unknown Status</div>
          </div>
        </div>

        <h3>Key Recommendations</h3>
        <ul class="recommendations">
          <li><strong>Patch immediately:</strong> Address CRITICAL and HIGH vulnerabilities through OS package updates (<code>apt-get update && apt-get upgrade</code>)</li>
          <li><strong>Enable automatic security updates:</strong> Install and configure <code>unattended-upgrades</code> for automatic security patch application</li>
          <li><strong>Review vulnerable packages:</strong> Run <code>oscap oval eval --report report.html oval.xml</code> for full per-CVE details</li>
          <li><strong>Rebuild containers:</strong> Update base images and rebuild pods with known CVEs in container layers</li>
        </ul>
        """

    recommendations_compliance = """
    <h3>Compliance Recommendations</h3>
    <ul class="recommendations">
      <li><strong>Run CIS hardening:</strong> Apply automated CIS Level 1 hardening via Ansible (<code>playbooks/20_cis_hardening.yml</code>)</li>
      <li><strong>Disable unused services:</strong> Remove non-essential packages and daemons exposed in the failed rules</li>
      <li><strong>Audit regularly:</strong> Schedule weekly OpenSCAP scans and track compliance trend over time</li>
      <li><strong>Fix failed rules:</strong> Each failed rule in the table above has corresponding Ansible remediation content in the SSG</li>
      <li><strong>Monitor drift:</strong> Use Prometheus node-exporter + Alertmanager to detect configuration drift from hardened state</li>
    </ul>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OpenSCAP Security Summary - {hostname}</title>
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
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
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
    font-size: 2.5rem;
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
  .bar-container {{
    background: #333;
    height: 8px;
    border-radius: 4px;
    margin-top: 0.75rem;
    overflow: hidden;
  }}
  .bar {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s;
  }}
  .bar-green {{ background: var(--green); }}
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
  .badge {{
    display: inline-block;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: bold;
    text-transform: uppercase;
  }}
  .badge-fail {{ background: var(--red); color: #fff; }}
  .badge-pass {{ background: var(--green); color: #000; }}
  .badge-green {{ background: var(--green); color: #000; }}
  .badge-red {{ background: var(--red); color: #fff; }}
  .badge-orange {{ background: var(--orange); color: #000; }}
  .badge-yellow {{ background: var(--yellow); color: #000; }}
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
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>OpenSCAP Security Summary</h1>
      <div class="header-info">Host: <strong>{hostname}</strong> | Profile: <strong>{c.get('profile', 'N/A') if c else 'N/A'}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
  </div>

  {compliance_html}

  {vuln_html}

  {recommendations_compliance}

  <footer style="text-align:center; color:#666; margin-top:3rem; font-size:0.8rem;">
    Generated by OpenSCAP Reporter | Ansible + k8s-security-reporting skill
  </footer>
</body>
</html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"Generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Parse OpenSCAP results and generate HTML summary")
    parser.add_argument("--input", required=True, help="Path to XCCDF results XML")
    parser.add_argument("--vuln", default=None, help="Path to OVAL vulnerability results XML")
    parser.add_argument("--hostname", required=True, help="Target hostname")
    parser.add_argument("--output", required=True, help="Output HTML file path")
    args = parser.parse_args()

    compliance_data, err = parse_xccdf(args.input)
    if err:
        print(f"Warning: {err}")

    vuln_data = None
    if args.vuln and Path(args.vuln).exists():
        vuln_data, err = parse_oval(args.vuln)
        if err:
            print(f"Warning parsing OVAL: {err}")

    generate_html(args.hostname, compliance_data, vuln_data, args.output)

if __name__ == "__main__":
    main()
