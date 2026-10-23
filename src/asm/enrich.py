"""Enrich findings with CISA KEV and FIRST EPSS data.

Usage (from the project root):
    python3 -m src.asm.enrich [--db asm.db]
"""
import argparse
import time

import requests

from .db import connect

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # keeps the cve parameter under the API's 2000-character limit
HEADERS = {"User-Agent": "asm-pipeline-lab (student portfolio project)"}
TIMEOUT = 30  # seconds


def finding_cves(con):
    """Return a sorted list of every unique CVE referenced by any finding."""
    cves = set()
    for (cve_list,) in con.execute("SELECT cves FROM findings WHERE cves IS NOT NULL"):
        for cve in cve_list.split(","):
            cves.add(cve.strip())
    return sorted(cves)


def refresh_kev(con):
    """Download the full KEV catalog and replace the kev table with it."""
    response = requests.get(KEV_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    catalog = response.json()

    rows = []
    for vuln in catalog["vulnerabilities"]:
        rows.append((
            vuln["cveID"],
            vuln.get("vendorProject"),
            vuln.get("product"),
            vuln.get("vulnerabilityName"),
            vuln.get("dateAdded"),
            vuln.get("dueDate"),
            vuln.get("knownRansomwareCampaignUse"),
        ))

    with con:
        con.execute("DELETE FROM kev")
        con.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    return catalog.get("catalogVersion"), len(rows)


EPSS_UPSERT = """
INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET
    epss       = excluded.epss,
    percentile = excluded.percentile,
    score_date = excluded.score_date
"""


def refresh_epss(con, cves):
    """Fetch EPSS scores for the given CVEs in batches. Return how many were stored."""
    stored = 0
    for start in range(0, len(cves), EPSS_BATCH_SIZE):
        batch = cves[start:start + EPSS_BATCH_SIZE]
        response = requests.get(
            EPSS_URL, params={"cve": ",".join(batch)}, headers=HEADERS, timeout=TIMEOUT
        )
        response.raise_for_status()

        rows = []
        for item in response.json()["data"]:
            rows.append((item["cve"], float(item["epss"]), float(item["percentile"]), item.get("date")))

        with con:
            con.executemany(EPSS_UPSERT, rows)
        stored += len(rows)
        time.sleep(1)  # be polite to a free public API
    return stored


def main():
    parser = argparse.ArgumentParser(description="Download KEV and EPSS data for current findings.")
    parser.add_argument("--db", default="asm.db", help="SQLite database path (default: asm.db)")
    args = parser.parse_args()

    con = connect(args.db)

    kev_version, kev_count = refresh_kev(con)
    print(f"KEV catalog {kev_version}: {kev_count} entries loaded")

    cves = finding_cves(con)
    print(f"Findings reference {len(cves)} unique CVEs")

    epss_count = refresh_epss(con, cves)
    print(f"EPSS scores stored: {epss_count} (CVEs without a score: {len(cves) - epss_count})")

    kev_cves = {row[0] for row in con.execute("SELECT cve FROM kev")}
    in_kev = [cve for cve in cves if cve in kev_cves]
    print(f"{len(in_kev)} of {len(cves)} finding CVEs are in CISA KEV")
    con.close()


if __name__ == "__main__":
    main()