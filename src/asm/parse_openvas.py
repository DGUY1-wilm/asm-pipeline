"""Parse an OpenVAS (GVM) XML report and store findings in SQLite.

Usage (from the project root):
    python3 -m src.asm.parse_openvas scans/openvas_*.xml [--db asm.db]
"""
import argparse
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone

from .db import connect

SCANNER = "openvas"


def scan_time_from(report):
    """Return the scan start time as an ISO 8601 UTC string."""
    text = report.findtext("scan_start")
    if text:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    else:
        moment = datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_result(result):
    """Turn one <result> element into a finding dict, or None to skip it."""
    severity = float(result.findtext("severity") or 0)
    if severity <= 0:
        return None  # "Log" results are informational, not vulnerabilities

    host = result.find("host")
    nvt = result.find("nvt")
    if host is None or host.text is None or nvt is None:
        return None
    ip = host.text.strip()  # the IP is the text before the nested <asset> element

    cves = []
    for ref in nvt.findall("refs/ref"):
        if ref.get("type") == "cve":
            cves.append(ref.get("id"))

    qod_text = result.findtext("qod/value")
    solution = (nvt.findtext("solution") or "").strip()

    return {
        "ip": ip,
        "port": result.findtext("port") or "general",
        "check_id": nvt.get("oid"),
        "name": result.findtext("name") or nvt.findtext("name"),
        "severity": severity,
        "severity_label": result.findtext("threat"),
        "cves": ",".join(cves) or None,
        "qod": int(qod_text) if qod_text else None,
        "solution": solution or None,
    }


def parse_report(xml_path):
    """Read one GVM report. Return (scan_time, total_results, findings)."""
    root = ET.parse(xml_path).getroot()
    report = root.find("report/report")
    if report is None:
        raise SystemExit(f"{xml_path}: no <report><report> element; is this a GVM report?")

    scan_time = scan_time_from(report)
    results = report.findall("results/result")
    findings = []
    for result in results:
        finding = parse_result(result)
        if finding is not None:
            findings.append(finding)
    return scan_time, len(results), findings


FINDING_UPSERT = """
INSERT INTO findings (ip, port, scanner, check_id, name, severity, severity_label,
                      cves, qod, solution, first_seen, last_seen)
VALUES (:ip, :port, :scanner, :check_id, :name, :severity, :severity_label,
        :cves, :qod, :solution, :seen, :seen)
ON CONFLICT(ip, port, scanner, check_id) DO UPDATE SET
    name           = excluded.name,
    severity       = excluded.severity,
    severity_label = excluded.severity_label,
    cves           = excluded.cves,
    qod            = excluded.qod,
    solution       = excluded.solution,
    first_seen     = MIN(first_seen, excluded.first_seen),
    last_seen      = MAX(last_seen, excluded.last_seen)
"""


def save_findings(con, scan_time, findings):
    """Upsert all findings from one report in a single transaction."""
    with con:
        for finding in findings:
            con.execute(FINDING_UPSERT, {**finding, "scanner": SCANNER, "seen": scan_time})


def main():
    parser = argparse.ArgumentParser(description="Load OpenVAS XML reports into SQLite.")
    parser.add_argument("xml_files", nargs="+", help="OpenVAS report XML file(s)")
    parser.add_argument("--db", default="asm.db", help="SQLite database path (default: asm.db)")
    args = parser.parse_args()

    con = connect(args.db)
    for path in args.xml_files:
        scan_time, total, findings = parse_report(path)
        save_findings(con, scan_time, findings)
        print(f"{path}: {total} results, {len(findings)} findings stored "
              f"(severity > 0), scan started {scan_time}")
        counts = Counter(finding["severity_label"] for finding in findings)
        for label, count in counts.most_common():
            print(f"  {label}: {count}")
    con.close()


if __name__ == "__main__":
    main()