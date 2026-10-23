"""Prioritize findings with CVSS, CISA KEV, and EPSS, then assign owners and due dates.

Usage (from the project root):
    python3 -m src.asm.score [--db asm.db] [--owners config/owners.yaml] [--sla config/sla.yaml]
"""
import argparse
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import yaml

from .db import connect

# Tunable thresholds (document any changes in the README).
CRITICAL_CVSS = 9.0
HIGH_CVSS = 7.0
MEDIUM_CVSS = 4.0
LIKELY_EPSS = 0.5
NOTABLE_EPSS = 0.1

# Findings an attacker can use without any exploit: just connect or log in.
DIRECT_COMPROMISE = re.compile(r"backdoor|default credential|passwordless", re.IGNORECASE)


def score_finding(finding, kev, epss):
    """Return (priority, sort_score, in_kev, max_epss, reason) for one finding."""
    cvss = finding["severity"]
    cves = finding["cves"].split(",") if finding["cves"] else []

    kev_hits = [cve for cve in cves if cve in kev]
    ransomware = any(kev[cve] == "Known" for cve in kev_hits)
    epss_values = [epss[cve] for cve in cves if cve in epss]
    max_epss = max(epss_values) if epss_values else None
    direct = bool(DIRECT_COMPROMISE.search(finding["name"]))
    likely = (max_epss or 0) >= LIKELY_EPSS
    notable = (max_epss or 0) >= NOTABLE_EPSS

    reasons = [f"CVSS {cvss:.1f}"]
    if kev_hits:
        reasons.append(f"{len(kev_hits)} CVE(s) in CISA KEV"
                       + (", ransomware use known" if ransomware else ""))
    if max_epss is not None:
        reasons.append(f"max EPSS {max_epss:.2f}")
    if not cves:
        reasons.append("no CVE")
    if direct:
        reasons.append("direct compromise (backdoor/default credentials)")

    if kev_hits or (cvss >= CRITICAL_CVSS and (likely or direct)):
        priority = "P1"
    elif cvss >= CRITICAL_CVSS or (cvss >= HIGH_CVSS and notable):
        priority = "P2"
    elif cvss >= MEDIUM_CVSS:
        priority = "P3"
    else:
        priority = "P4"

    # A direct-compromise finding needs no exploit, so treat its likelihood as certain.
    sort_epss = 1.0 if direct else (max_epss or 0)
    sort_score = min(1.0, 0.6 * (cvss / 10) + 0.4 * sort_epss + (0.1 if ransomware else 0))
    return priority, round(sort_score, 3), bool(kev_hits), max_epss, "; ".join(reasons)


def load_yaml(path):
    """Read a YAML config file safely."""
    with open(path) as f:
        return yaml.safe_load(f)


def owner_for(ip, owners):
    """Return the owner entry for an IP, or the default triage owner."""
    return owners.get("assets", {}).get(ip) or owners["default_owner"]


def due_date(first_seen, sla_days):
    """The SLA clock starts when the finding was first seen."""
    start = datetime.strptime(first_seen, "%Y-%m-%dT%H:%M:%SZ")
    return (start + timedelta(days=sla_days)).strftime("%Y-%m-%d")


INSERT_SCORE = """
INSERT INTO finding_scores (ip, port, scanner, check_id, priority, sort_score, in_kev,
                            max_epss, reason, owner_team, owner_contact, sla_days,
                            due_date, scored_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def main():
    parser = argparse.ArgumentParser(description="Score findings and assign owners and due dates.")
    parser.add_argument("--db", default="asm.db", help="SQLite database path")
    parser.add_argument("--owners", default="config/owners.yaml", help="Asset ownership config")
    parser.add_argument("--sla", default="config/sla.yaml", help="SLA days per priority")
    args = parser.parse_args()

    owners = load_yaml(args.owners)
    sla = load_yaml(args.sla)

    con = connect(args.db)
    kev = {cve: ransomware for cve, ransomware in con.execute("SELECT cve, ransomware FROM kev")}
    epss = {cve: score for cve, score in con.execute("SELECT cve, epss FROM epss")}
    scored_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = []
    query = "SELECT ip, port, scanner, check_id, name, severity, cves, first_seen FROM findings"
    for ip, port, scanner, check_id, name, severity, cves, first_seen in con.execute(query):
        finding = {"name": name, "severity": severity, "cves": cves}
        priority, sort_score, in_kev, max_epss, reason = score_finding(finding, kev, epss)
        owner = owner_for(ip, owners)
        rows.append((ip, port, scanner, check_id, priority, sort_score, int(in_kev), max_epss,
                     reason, owner["team"], owner["contact"], sla[priority],
                     due_date(first_seen, sla[priority]), scored_at))

    with con:
        con.execute("DELETE FROM finding_scores")
        con.executemany(INSERT_SCORE, rows)

    counts = Counter(row[4] for row in rows)
    print(f"Scored {len(rows)} findings at {scored_at}")
    for priority in sorted(counts):
        print(f"  {priority}: {counts[priority]} (due within {sla[priority]} days)")
    con.close()


if __name__ == "__main__":
    main()