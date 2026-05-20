#!/usr/bin/env python3
"""
Parse Kubescape JSON scan results and generate an HTML summary dashboard.
Reads from reports/kubescape/<hostname>/ directory.
Generates reports/summary_kubescape.html
"""
import json
import glob
import os
import sys
from collections import defaultdict
from datetime import datetime

def severity_rank(sev):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(sev, 0)

def load_reports(base_dir):
    reports = []
    pattern = os.path.join(base_dir, "kubescape", "*", "*.json")
    for path in glob.glob(pattern):
        hostname = path.split("/")[-2]
        scan_name = os.path.basename(path).replace(".json", "")
        with open(path, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue
        reports.append({
            "path": path,
            "hostname": hostname,
            "scan_name": scan_name,
            "data": data
        })
    return reports

def summarize_control(ctrl):
    status_info = ctrl.get("statusInfo", {})
    status = status_info.get("status", "unknown")
    counters = ctrl.get("ResourceCounters", {})
    return {
        "id": ctrl.get("controlID", "?"),
        "name": ctrl.get("name", "Unknown"),
        "status": status,
        "severity": ctrl.get("severity", "Unknown"),
        "category": ctrl.get("category", {}).get("name", "Unknown"),
        "passed": counters.get("passedResources", 0),
        "failed": counters.get("failedResources", 0),
        "score": round(ctrl.get("complianceScore", 0), 1),
    }

def build_openscap_summary():
    base_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    if not os.path.isdir(base_dir):
        base_dir = "reports"
    
    nodes_dir = os.path.join(base_dir, "openscap", "nodes")
    if not os.path.isdir(nodes_dir):
        return None, "No OpenSCAP reports found in " + nodes_dir
    
    hosts = []
    total_pass = 0
    total_fail = 0
    total_error = 0
    total_notchecked = 0
    total_unknown = 0
    vuln_cves = []
    
    # Find all .xml report files
    xml_files = glob.glob(os.path.join(nodes_dir, "*", "*.xml"))
    
    for xf in xml_files:
        parts = xf.replace(nodes_dir, "").strip("/").split("/")
        if len(parts) >= 2:
            host = parts[0]
        else:
            host = "unknown"
        
        # Quick regex parse (no heavy xml dep)
        import re
        content = open(xf, "r", errors="ignore").read()
        
        # Result counts
        pass_c = len(re.findall(r'result="pass"', content))
        fail_c = len(re.findall(r'result="fail"', content))
        err_c = len(re.findall(r'result="error"', content))
        nc_c = len(re.findall(r'result="notchecked"', content))
        unk_c = len(re.findall(r'result="unknown"', content))
        
        total_pass += pass_c
        total_fail += fail_c
        total_error += err_c
        total_notchecked += nc_c
        total_unknown += unk_c
        
        hosts.append({
            "name": host,
            "pass": pass_c,
            "fail": fail_c,
            "error": err_c,
            "notchecked": nc_c,
            "unknown": unk_c,
            "score": round((pass_c / max(pass_c + fail_c, 1)) * 100, 1)
        })
    
    overall_score = round((total_pass / max(total_pass + total_fail, 1)) * 100, 1)
    
    summary = {
        "scan_type": "OpenSCAP Node Compliance + Vulnerability",
        "hosts": hosts,
        "totals": {
            "pass": total_pass,
            "fail": total_fail,
            "error": total_error,
            "notchecked": total_notchecked,
            "unknown": total_unknown,
            "score": overall_score
        }
    }
    return summary, None

def build_kubescape_summary(base_dir="reports"):
    reports = load_reports(base_dir)
    if not reports:
        return None, f"No Kubescape JSON reports found under {base_dir}/kubescape/"

    # Aggregate across all reports
    controls_all = {}
    frameworks = set()
    severity_counts = defaultdict(int)
    category_counts = defaultdict(lambda: {"passed": 0, "failed": 0, "total": 0})
    host_scores = {}
    scan_scores = {}

    for rep in reports:
        data = rep["data"]
        hostname = rep["hostname"]
        scan_name = rep["scan_name"]

        # Score per host-scan
        score = round(data.get("summaryDetails", {}).get("complianceScore", 0), 1)
        key = (hostname, scan_name)
        scan_scores[key] = score
        if hostname not in host_scores or score < host_scores[hostname]:
            host_scores[hostname] = score

        controls = data.get("summaryDetails", {}).get("controls", {})
        for cid, ctrl in controls.items():
            s = summarize_control(ctrl)
            if cid not in controls_all:
                controls_all[cid] = s
            else:
                # Merge: worst status wins, sum counts
                if s["status"] == "failed" and controls_all[cid]["status"] != "failed":
                    controls_all[cid]["status"] = "failed"
                controls_all[cid]["passed"] += s["passed"]
                controls_all[cid]["failed"] += s["failed"]
                controls_all[cid]["score"] = min(controls_all[cid]["score"], s["score"])

            sev = s["severity"]
            if s["status"] == "failed":
                severity_counts[sev] += 1
            cat = s["category"]
            category_counts[cat]["total"] += 1
            if s["status"] == "passed":
                category_counts[cat]["passed"] += 1
            else:
                category_counts[cat]["failed"] += 1

        # Frameworks
        frameworks_data = data.get("summaryDetails", {}).get("frameworks", [])
        if isinstance(frameworks_data, list):
            for fw_item in frameworks_data:
                if isinstance(fw_item, dict) and "name" in fw_item:
                    frameworks.add(fw_item["name"])
        elif isinstance(frameworks_data, dict):
            for k, v in frameworks_data.items():
                frameworks.add(k if isinstance(v, dict) else str(k))
        else:
            try:
                frameworks.add(str(frameworks_data))
            except (TypeError, ValueError):
                pass

    failed_controls = [c for c in controls_all.values() if c["status"] == "failed"]
    passed_controls = [c for c in controls_all.values() if c["status"] == "passed"]
    skipped_controls = [c for c in controls_all.values() if c["status"] == "skipped"]

    failed_controls.sort(key=lambda x: (severity_rank(x["severity"]), x["name"]))

    total_resources = 0
    failed_resources = 0
    for rep in reports:
        rc = rep["data"].get("summaryDetails", {}).get("ResourceCounters", {})
        total_resources += rc.get("passedResources", 0) + rc.get("failedResources", 0)
        failed_resources += rc.get("failedResources", 0)

    avg_score = round(sum(scan_scores.values()) / max(len(scan_scores), 1), 1)

    return {
        "scan_type": "Kubescape Cluster Security",
        "report_count": len(reports),
        "frameworks": sorted(frameworks),
        "hosts": sorted(host_scores.keys()),
        "host_scores": host_scores,
        "scan_scores": scan_scores,
        "avg_score": avg_score,
        "total_controls": len(controls_all),
        "passed": len(passed_controls),
        "failed": len(failed_controls),
        "skipped": len(skipped_controls),
        "total_resources": total_resources,
        "failed_resources": failed_resources,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "failed_controls": failed_controls,
        "passed_controls": passed_controls,
    }, None


def render_openscap_html(summary, out_path):
    hosts = summary["hosts"]
    totals = summary["totals"]
    
    rows = ""
    for h in hosts:
        rows += f"""
        <tr>
          <td>{h['name']}</td>
          <td class="pass">{h['pass']}</td>
          <td class="fail">{h['fail']}</td>
          <td>{h['error']}</td>
          <td>{h['notchecked']}</td>
          <td><b>{h['score']}%</b></td>
        </tr>"""
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>OpenSCAP Node Scan Summary</title>
<style>
:root {{ --bg:#0b0f19; --card:#121929; --text:#c9d1d9; --muted:#8b949e; --pass:#3fb950; --fail:#f85149; --warn:#d29922; --accent:#58a6ff;}}
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:30px; }}
h1 {{ color:var(--accent); }} h2 {{ color:var(--text); border-bottom:1px solid #30363d; padding-bottom:8px; }}
.card {{ background:var(--card); border-radius:10px; padding:20px; margin:20px 0; border:1px solid #21262d; }}
table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
th,td {{ padding:10px; text-align:left; border-bottom:1px solid #21262d; }}
th {{ color:var(--muted); font-weight:600; }}
.pass {{ color:var(--pass); }} .fail {{ color:var(--fail); }} .warn {{ color:var(--warn); }}
.score-box {{ font-size:2.5rem; font-weight:700; color:var(--accent); }}
.metric {{ display:inline-block; margin:10px 20px 0 0; }}
.metric span {{ display:block; font-size:1.8rem; font-weight:700; }}
.metric label {{ color:var(--muted); font-size:0.85rem; }}
</style></head><body>
<h1>OpenSCAP Node Compliance + Vulnerability Summary</h1>
<p>Generated: {datetime.now().isoformat()}</p>

<div class="card">
  <div class="score-box">{totals['score']}%</div>
  <p class="muted">Overall Compliance Score (pass / (pass + fail))</p>
  <div class="metric"><span class="pass">{totals['pass']}</span><label>Passed</label></div>
  <div class="metric"><span class="fail">{totals['fail']}</span><label>Failed</label></div>
  <div class="metric"><span>{totals['error']}</span><label>Errors</label></div>
  <div class="metric"><span>{totals['notchecked']}</span><label>Not Checked</label></div>
</div>

<div class="card">
  <h2>Per-Node Breakdown</h2>
  <table>
    <tr><th>Node</th><th>Passed</th><th>Failed</th><th>Errors</th><th>Not Checked</th><th>Score</th></tr>
    {rows}
  </table>
</div>

<div class="card">
  <h2>Recommendations</h2>
  <ul>
    <li>Address <b>failed</b> rules to improve compliance posture. Focus on High/Critical severity findings first.</li>
    <li>Investigate any <b>error</b> results — these indicate scan probe failures (missing files, permissions).</li>
    <li>Review <b>not checked</b> items manually; many require documented compensating controls.</li>
    <li>Run <code>oscap xccdf eval --remediate</code> for automatic fix of supported rules.</li>
    <li>Consider enabling canonical OVAL feeds if internet access allows for up-to-date CVE data.</li>
  </ul>
</div>
</body></html>"""
    with open(out_path, "w") as f:
        f.write(html)
    print(f"OpenSCAP summary written to {out_path}")


def render_kubescape_html(summary, out_path):
    fc = summary["failed_controls"]
    sev = summary["severity_counts"]
    cat = summary["category_counts"]
    
    failed_rows = ""
    for c in fc:
        sev_class = c["severity"].lower()
        failed_rows += f"""
        <tr>
          <td><code>{c['id']}</code></td>
          <td>{c['name']}</td>
          <td class="{sev_class}">{c['severity']}</td>
          <td>{c['category']}</td>
          <td class="fail">{c['failed']}</td>
          <td>{c['score']}%</td>
        </tr>"""
    
    cat_rows = ""
    for name, vals in sorted(cat.items(), key=lambda x: x[1]["failed"], reverse=True):
        cat_rows += f"""
        <tr>
          <td>{name}</td>
          <td class="pass">{vals['passed']}</td>
          <td class="fail">{vals['failed']}</td>
          <td>{vals['total']}</td>
        </tr>"""
    
    host_rows = ""
    for h in summary["hosts"]:
        score = summary["host_scores"].get(h, 0)
        host_rows += f"<tr><td>{h}</td><td><b>{score}%</b></td></tr>"
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Kubescape Security Scan Summary</title>
<style>
:root {{ --bg:#0b0f19; --card:#121929; --text:#c9d1d9; --muted:#8b949e; --pass:#3fb950; --fail:#f85149; --warn:#d29922; --accent:#58a6ff; --critical:#f85149; --high:#f85149; --medium:#d29922; --low:#58a6ff;}}
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:30px; }}
h1 {{ color:var(--accent); }} h2 {{ color:var(--text); border-bottom:1px solid #30363d; padding-bottom:8px; }}
.card {{ background:var(--card); border-radius:10px; padding:20px; margin:20px 0; border:1px solid #21262d; }}
table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
th,td {{ padding:10px; text-align:left; border-bottom:1px solid #21262d; }}
th {{ color:var(--muted); font-weight:600; }}
.pass {{ color:var(--pass); }} .fail {{ color:var(--fail); }} .warn {{ color:var(--warn); }}
.critical {{ color:var(--critical); font-weight:700; }} .high {{ color:var(--high); }} .medium {{ color:var(--medium); }} .low {{ color:var(--low); }}
.score-box {{ font-size:2.5rem; font-weight:700; color:var(--accent); }}
.metric {{ display:inline-block; margin:10px 20px 0 0; }}
.metric span {{ display:block; font-size:1.8rem; font-weight:700; }}
.metric label {{ color:var(--muted); font-size:0.85rem; }}
</style></head><body>
<h1>Kubescape Cluster Security Summary</h1>
<p>Generated: {datetime.now().isoformat()} | Scans: {summary['report_count']} | Frameworks: {', '.join(summary['frameworks']) or 'N/A'}</p>

<div class="card">
  <div class="score-box">{summary['avg_score']}%</div>
  <p class="muted">Average Compliance Score across all scans</p>
  <div class="metric"><span class="pass">{summary['passed']}</span><label>Passed Controls</label></div>
  <div class="metric"><span class="fail">{summary['failed']}</span><label>Failed Controls</label></div>
  <div class="metric"><span>{summary['skipped']}</span><label>Skipped Controls</label></div>
  <div class="metric"><span>{summary['total_resources']}</span><label>Resources Checked</label></div>
  <div class="metric"><span class="fail">{summary['failed_resources']}</span><label>Failed Resources</label></div>
</div>

<div class="card">
  <h2>Severity Breakdown (Failed Controls)</h2>
  <div class="metric"><span class="critical">{sev.get('Critical', 0)}</span><label>Critical</label></div>
  <div class="metric"><span class="high">{sev.get('High', 0)}</span><label>High</label></div>
  <div class="metric"><span class="medium">{sev.get('Medium', 0)}</span><label>Medium</label></div>
  <div class="metric"><span class="low">{sev.get('Low', 0)}</span><label>Low</label></div>
</div>

<div class="card">
  <h2>Per-Node Scores</h2>
  <table>
    <tr><th>Node</th><th>Worst Scan Score</th></tr>
    {host_rows}
  </table>
</div>

<div class="card">
  <h2>Findings by Category</h2>
  <table>
    <tr><th>Category</th><th>Passed</th><th>Failed</th><th>Total Controls</th></tr>
    {cat_rows}
  </table>
</div>

<div class="card">
  <h2>Failed Controls (sorted by severity)</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Severity</th><th>Category</th><th>Failed Resources</th><th>Score</th></tr>
    {failed_rows}
  </table>
</div>

<div class="card">
  <h2>Top Recommendations</h2>
  <ul>
    <li><b>Control Plane:</b> Enable audit logs, encrypt etcd secrets, disable anonymous access, enforce Kubelet TLS.</li>
    <li><b>Access Control:</b> Minimize wildcard use in RBAC, restrict secret listing, limit pod creation privileges.</li>
    <li><b>Workload:</b> Set CPU/memory limits, run non-root containers, drop unnecessary capabilities, avoid privileged mode.</li>
    <li><b>Network:</b> Apply NetworkPolicies, restrict HostNetwork/HostPID, block ingress/egress as needed.</li>
    <li><b>Storage:</b> Eliminate writable hostPath mounts, validate admission controllers.</li>
    <li><b>Next step:</b> Install the Kubescape operator for continuous monitoring and automated remediation.</li>
  </ul>
</div>
</body></html>"""
    with open(out_path, "w") as f:
        f.write(html)
    print(f"Kubescape summary written to {out_path}")


def main():
    base_dir = os.environ.get("REPORTS_DIR", "reports")
    if not os.path.isdir(base_dir):
        # Try relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(script_dir, "..", "reports")
        if not os.path.isdir(base_dir):
            base_dir = "."

    # OpenSCAP
    oscap_summary, oscap_err = build_openscap_summary()
    if oscap_summary:
        render_openscap_html(oscap_summary, os.path.join(base_dir, "summary_openscap.html"))
    else:
        print("OpenSCAP:", oscap_err or "No data")
        # Write placeholder
        with open(os.path.join(base_dir, "summary_openscap.html"), "w") as f:
            f.write(f"""<!DOCTYPE html><html><body style="background:#0b0f19;color:#c9d1d9;font-family:sans-serif;padding:40px;">
            <h1>OpenSCAP Summary</h1><p>No reports found yet. Run playbook 30_node_openscap_scan.yml first.</p>
            <p>{datetime.now().isoformat()}</p></body></html>""")

    # Kubescape
    ks_summary, ks_err = build_kubescape_summary(base_dir)
    if ks_summary:
        render_kubescape_html(ks_summary, os.path.join(base_dir, "summary_kubescape.html"))
    else:
        print("Kubescape:", ks_err or "No data")
        with open(os.path.join(base_dir, "summary_kubescape.html"), "w") as f:
            f.write(f"""<!DOCTYPE html><html><body style="background:#0b0f19;color:#c9d1d9;font-family:sans-serif;padding:40px;">
            <h1>Kubescape Summary</h1><p>No reports found yet. Run playbook 32_kubescape_scan.yml first.</p>
            <p>{datetime.now().isoformat()}</p></body></html>""")


if __name__ == "__main__":
    main()
