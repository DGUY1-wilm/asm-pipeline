"""Generate a self-contained HTML report of assets and prioritized findings.

Usage (from the project root):
    python3 -m src.asm.report [--db asm.db] [--owners config/owners.yaml] [--out-dir reports]
"""
import argparse
import os
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from html import escape

from .db import connect
from .score import load_yaml, owner_for

PRIORITIES = ["P1", "P2", "P3", "P4"]

CSS = """
:root { --bg:#ffffff; --fg:#1d1d1f; --muted:#666; --border:#ddd; --card:#f3f4f6;
        --p1:#c0392b; --p2:#d35400; --p3:#9a7d0a; --p4:#2874a6; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181d; --fg:#e8e8e8; --muted:#9aa0a6; --border:#333; --card:#22252b;
          --p1:#ff6b5b; --p2:#ff9f43; --p3:#f4d03f; --p4:#5dade2; }
}
body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg);
       margin: 2rem auto; padding: 0 1rem; max-width: 1300px; }
.meta { color: var(--muted); }
.cards { display: flex; flex-wrap: wrap; gap: 1rem; margin: 1.5rem 0; }
.card { background: var(--card); border-radius: 8px; padding: 0.8rem 1.2rem; min-width: 110px; }
.card .num { font-size: 1.8rem; font-weight: 700; }
.card .label { color: var(--muted); font-size: 0.85rem; }
.scroll { overflow-x: auto; margin-bottom: 2rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
th, td { border-bottom: 1px solid var(--border); padding: 0.4rem 0.6rem;
         text-align: left; vertical-align: top; }
th { background: var(--card); }
tr.P1 td:first-child { color: var(--p1); font-weight: 700; }
tr.P2 td:first-child { color: var(--p2); font-weight: 700; }
tr.P3 td:first-child { color: var(--p3); font-weight: 700; }
tr.P4 td:first-child { color: var(--p4); font-weight: 700; }
"""

ASSETS_QUERY = """
SELECT a.ip, a.vendor, a.os_name, a.first_seen, a.last_seen, COUNT(s.port)
FROM assets a LEFT JOIN services s ON s.ip = a.ip
GROUP BY a.ip ORDER BY a.ip
"""

FINDINGS_QUERY = """
SELECT s.priority, s.ip, f.port, f.name, f.severity, s.in_kev, s.max_epss,
       s.owner_team, s.due_date, s.reason
FROM finding_scores s JOIN findings f USING (ip, port, scanner, check_id)
ORDER BY s.priority, s.sort_score DESC
"""


def status_for(due, today):
    """Classify a due date relative to today."""
    days_left = (date.fromisoformat(due) - today).days
    if days_left < 0:
        return "Overdue"
    if days_left <= 3:
        return "Due soon"
    return "On track"


def table(headers, rows, row_classes=None):
    """Build an HTML table. Every cell is escaped, because scan data is untrusted."""
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = []
    for i, row in enumerate(rows):
        css = f' class="{row_classes[i]}"' if row_classes else ""
        cells = "".join(f"<td>{escape(str(cell))}</td>" for cell in row)
        body.append(f"<tr{css}>{cells}</tr>")
    return (f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def main():
    parser = argparse.ArgumentParser(description="Generate the HTML ASM report.")
    parser.add_argument("--db", default="asm.db", help="SQLite database path")
    parser.add_argument("--owners", default="config/owners.yaml", help="Asset ownership config")
    parser.add_argument("--out-dir", default="reports", help="Where to write the report")
    args = parser.parse_args()

    owners = load_yaml(args.owners)
    inventory = owners.get("assets", {})
    today = datetime.now(timezone.utc).date()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    con = connect(args.db)

    asset_rows = []
    unowned = 0
    for ip, vendor, os_name, first_seen, last_seen, service_count in con.execute(ASSETS_QUERY):
        owner = owner_for(ip, owners)
        if ip not in inventory:
            unowned += 1
        asset_rows.append((ip, owner.get("name", "(not in inventory)"), owner["team"],
                           vendor or "", os_name or "unknown", service_count,
                           first_seen, last_seen))

    finding_rows, row_classes = [], []
    priority_counts = Counter()
    workload = defaultdict(Counter)
    kev_count = overdue = 0
    for priority, ip, port, name, cvss, in_kev, max_epss, team, due, reason in con.execute(FINDINGS_QUERY):
        status = status_for(due, today)
        priority_counts[priority] += 1
        workload[team][priority] += 1
        kev_count += in_kev
        overdue += status == "Overdue"
        finding_rows.append((priority, ip, port, name, f"{cvss:.1f}", "Yes" if in_kev else "",
                             f"{max_epss:.2f}" if max_epss is not None else "",
                             team, due, status, reason))
        row_classes.append(priority)
    con.close()

    cards = [("Assets", len(asset_rows)), ("Unowned assets", unowned),
             ("Findings", sum(priority_counts.values()))]
    cards += [(p, priority_counts[p]) for p in PRIORITIES]
    cards += [("KEV-linked", kev_count), ("Overdue", overdue)]
    cards_html = "".join(
        f'<div class="card"><div class="num">{value}</div>'
        f'<div class="label">{escape(label)}</div></div>'
        for label, value in cards
    )

    workload_rows = [(team, *[counts[p] for p in PRIORITIES], sum(counts.values()))
                     for team, counts in sorted(workload.items())]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASM Report {today}</title>
<style>{CSS}</style>
</head>
<body>
<h1>Attack Surface Management Report</h1>
<p class="meta">Generated {escape(generated)} &middot; Scope: isolated lab network 192.168.56.0/24
&middot; Prioritized with CVSS, CISA KEV, and FIRST EPSS</p>
<div class="cards">{cards_html}</div>
<h2>Remediation workload by owner</h2>
{table(["Owner", *PRIORITIES, "Total"], workload_rows)}
<h2>Asset inventory</h2>
{table(["IP", "Name", "Owner", "NIC vendor", "OS guess", "Open services", "First seen", "Last seen"], asset_rows)}
<h2>Prioritized findings</h2>
{table(["Pri", "IP", "Port", "Finding", "CVSS", "KEV", "Max EPSS", "Owner", "Due", "Status", "Why"],
       finding_rows, row_classes)}
</body>
</html>
"""

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"asm_report_{today}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()