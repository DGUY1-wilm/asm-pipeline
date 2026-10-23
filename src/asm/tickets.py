"""Create and close Jira tickets for P1/P2 findings, one ticket per affected service.

Usage (from the project root, with JIRA_SITE, JIRA_EMAIL, and JIRA_TOKEN exported):
    python3 -m src.asm.tickets --dry-run            # preview new tickets
    python3 -m src.asm.tickets --project ASM        # create new tickets
    python3 -m src.asm.tickets --close --dry-run    # preview tickets that would close
    python3 -m src.asm.tickets --close              # close resolved tickets
"""
import argparse
import os
from collections import defaultdict
from datetime import datetime, timezone

import requests

from .db import connect
from .score import load_yaml, owner_for

TICKET_PRIORITIES = {"P1", "P2"}
JIRA_PRIORITY = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}
OPTIONAL_FIELDS = {"priority", "duedate"}  # some project types reject these
TIMEOUT = 30

QUERY = """
SELECT f.ip, f.port, f.name, f.severity, f.solution,
       s.priority, s.in_kev, s.reason, s.due_date
FROM finding_scores s JOIN findings f USING (ip, port, scanner, check_id)
ORDER BY s.priority, s.sort_score DESC
"""


def now_utc():
    """Current time as an ISO 8601 UTC string, matching the rest of the project."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jira_config():
    """Read Jira connection details from environment variables."""
    missing = [name for name in ("JIRA_SITE", "JIRA_EMAIL", "JIRA_TOKEN") if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"Missing environment variables: {', '.join(missing)}")
    site = os.environ["JIRA_SITE"].rstrip("/")
    return site, (os.environ["JIRA_EMAIL"], os.environ["JIRA_TOKEN"])


def group_findings(con):
    """Group scored findings by (ip, port). Each group's list is worst-first."""
    groups = defaultdict(list)
    for ip, port, name, severity, solution, priority, in_kev, reason, due in con.execute(QUERY):
        groups[(ip, port)].append({
            "name": name, "severity": severity, "solution": solution, "priority": priority,
            "in_kev": bool(in_kev), "reason": reason, "due_date": due,
        })
    return groups


def to_adf(lines):
    """Convert plain text lines to Atlassian Document Format, which Jira's v3 API requires."""
    content = []
    for line in lines:
        if line:
            content.append({"type": "paragraph", "content": [{"type": "text", "text": line}]})
        else:
            content.append({"type": "paragraph"})
    return {"type": "doc", "version": 1, "content": content}


def build_ticket(ip, port, findings, owners, project_key):
    """Return (priority, Jira fields) for one group of findings."""
    top = findings[0]
    priority = top["priority"]
    due = min(f["due_date"] for f in findings)
    owner = owner_for(ip, owners)
    asset = owner.get("name", ip)

    summary = f"[{priority}] {asset} {port}: {top['name']}"
    if len(findings) > 1:
        summary += f" (+{len(findings) - 1} related)"

    lines = [
        f"Asset: {asset} ({ip}), port {port}",
        f"Owner: {owner['team']} <{owner['contact']}>",
        f"Due: {due} (SLA for {priority})",
        "",
        "Findings, worst first:",
    ]
    for f in findings:
        lines.append(f"- [{f['priority']}] {f['name']} | {f['reason']}")
    if top["solution"]:
        lines += ["", f"Recommended fix (top finding): {top['solution']}"]
    lines += ["", "Created by asm-pipeline. Closed automatically when a rescan no longer detects these findings."]

    labels = ["asm-pipeline", priority.lower()]
    if any(f["in_kev"] for f in findings):
        labels.append("cisa-kev")

    fields = {
        "project": {"key": project_key},
        "issuetype": {"name": "Task"},
        "summary": summary[:250],
        "description": to_adf(lines),
        "labels": labels,
        "priority": {"name": JIRA_PRIORITY[priority]},
        "duedate": due,
    }
    return priority, fields


def create_issue(site, auth, fields):
    """Create a Jira issue and return its key, dropping optional fields Jira rejects."""
    url = f"{site}/rest/api/3/issue"
    response = requests.post(url, json={"fields": fields}, auth=auth, timeout=TIMEOUT)

    if response.status_code == 400:
        try:
            errors = response.json().get("errors", {})
        except ValueError:
            errors = {}
        if errors and set(errors) <= OPTIONAL_FIELDS:
            print(f"  note: this project rejects {sorted(errors)}; retrying without them")
            fields = {k: v for k, v in fields.items() if k not in errors}
            response = requests.post(url, json={"fields": fields}, auth=auth, timeout=TIMEOUT)

    if not response.ok:
        raise SystemExit(f"Jira error {response.status_code}: {response.text[:500]}")
    return response.json()["key"]


def create_tickets(con, owners, project_key, dry_run):
    """Create one ticket per P1/P2 service group that doesn't already have an open ticket."""
    groups = group_findings(con)
    open_services = set(con.execute("SELECT ip, port FROM tickets WHERE status = 'open'"))
    if not dry_run:
        site, auth = jira_config()

    created = skipped = 0
    for (ip, port), findings in groups.items():
        priority, fields = build_ticket(ip, port, findings, owners, project_key)
        if priority not in TICKET_PRIORITIES:
            continue
        if (ip, port) in open_services:
            skipped += 1
            continue
        if dry_run:
            print(f"[dry run] {fields['summary']} | due {fields['duedate']} | {len(findings)} finding(s)")
            continue

        key = create_issue(site, auth, fields)
        with con:
            con.execute(
                "INSERT INTO tickets (jira_key, ip, port, priority, status, created_at) "
                "VALUES (?, ?, ?, ?, 'open', ?)",
                (key, ip, port, priority, now_utc()),
            )
        print(f"Created {key}: {fields['summary']}")
        created += 1

    print(f"Done: {created} created, {skipped} skipped (already open)")


def close_issue(site, auth, key, note):
    """Comment on a Jira issue, then move it to a Done status."""
    base = f"{site}/rest/api/3/issue/{key}"
    response = requests.get(f"{base}/transitions", auth=auth, timeout=TIMEOUT)
    response.raise_for_status()
    done = [t for t in response.json()["transitions"]
            if t["to"]["statusCategory"]["key"] == "done"]
    if not done:
        raise SystemExit(f"{key}: no transition to a Done status is available")

    requests.post(f"{base}/comment", json={"body": to_adf([note])},
                  auth=auth, timeout=TIMEOUT).raise_for_status()
    requests.post(f"{base}/transitions", json={"transition": {"id": done[0]["id"]}},
                  auth=auth, timeout=TIMEOUT).raise_for_status()


def close_resolved(con, dry_run):
    """Close open tickets whose findings were absent from a newer scan of the same host."""
    if not dry_run:
        site, auth = jira_config()
    open_tickets = con.execute(
        "SELECT jira_key, ip, port FROM tickets WHERE status = 'open'"
    ).fetchall()

    closed = 0
    for key, ip, port in open_tickets:
        latest_scan = con.execute(
            "SELECT MAX(scan_time) FROM scan_runs WHERE ip = ?", (ip,)
        ).fetchone()[0]
        last_seen = con.execute(
            "SELECT MAX(last_seen) FROM findings WHERE ip = ? AND port = ?", (ip, port)
        ).fetchone()[0]
        if latest_scan is None or last_seen is None or last_seen >= latest_scan:
            continue  # never rescanned, or still detected

        note = (f"Resolved by asm-pipeline: the rescan at {latest_scan} no longer detects "
                f"findings on {ip} {port} (last seen {last_seen}).")
        if dry_run:
            print(f"[dry run] would close {key}: {note}")
            continue
        close_issue(site, auth, key, note)
        with con:
            con.execute("UPDATE tickets SET status = 'closed', closed_at = ? WHERE jira_key = ?",
                        (now_utc(), key))
        print(f"Closed {key}: {note}")
        closed += 1

    print(f"Done: {closed} ticket(s) closed")


def main():
    parser = argparse.ArgumentParser(description="Create or close Jira tickets for findings.")
    parser.add_argument("--db", default="asm.db", help="SQLite database path")
    parser.add_argument("--owners", default="config/owners.yaml", help="Asset ownership config")
    parser.add_argument("--project", default=os.environ.get("JIRA_PROJECT", "ASM"),
                        help="Jira project key (default: $JIRA_PROJECT or ASM)")
    parser.add_argument("--close", action="store_true",
                        help="Close tickets whose findings are gone in a newer scan")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without changing Jira")
    args = parser.parse_args()

    con = connect(args.db)
    if args.close:
        close_resolved(con, args.dry_run)
    else:
        create_tickets(con, load_yaml(args.owners), args.project, args.dry_run)
    con.close()


if __name__ == "__main__":
    main()