"""Parse Nmap XML output and store live hosts and open services in SQLite.

Usage (from the project root):
    python3 -m src.asm.parse_nmap scans/services_2026-10-22.xml [more.xml ...] [--db asm.db]
"""
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .db import connect


def attr(element, name):
    """Return an attribute's value, or None if the element itself is missing."""
    if element is None:
        return None
    return element.get(name)


def scan_time_from(root):
    """Return the scan's start time as an ISO 8601 UTC string."""
    start = root.get("start")  # Unix timestamp, e.g. "1792693811"
    if start is None:
        moment = datetime.now(timezone.utc)
    else:
        moment = datetime.fromtimestamp(int(start), tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_host(host):
    """Turn one <host> element into a dict, or return None to skip it."""
    if attr(host.find("status"), "state") != "up":
        return None

    ip = mac = vendor = None
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            ip = address.get("addr")
        elif address.get("addrtype") == "mac":
            mac = address.get("addr")
            vendor = address.get("vendor")
    if ip is None:
        return None

    services = []
    for port in host.findall("ports/port"):
        if attr(port.find("state"), "state") != "open":
            continue
        service = port.find("service")
        services.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": "open",
            "name": attr(service, "name"),
            "product": attr(service, "product"),
            "version": attr(service, "version"),
            "extra_info": attr(service, "extrainfo"),
        })

    # Nmap's OS detection needs at least one open and one closed port.
    # With no open ports its guesses are unreliable, so we store nothing.
    os_name = os_accuracy = None
    best_match = host.find("os/osmatch")
    if best_match is not None and services:
        os_name = best_match.get("name")
        os_accuracy = int(best_match.get("accuracy"))

    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": attr(host.find("hostnames/hostname"), "name"),
        "os_name": os_name,
        "os_accuracy": os_accuracy,
        "services": services,
    }


def parse_scan(xml_path):
    """Read one Nmap XML file. Return (scan_time, list of host dicts)."""
    root = ET.parse(xml_path).getroot()
    scan_time = scan_time_from(root)
    hosts = []
    for host_element in root.findall("host"):
        host = parse_host(host_element)
        if host is not None:
            hosts.append(host)
    return scan_time, hosts


ASSET_UPSERT = """
INSERT INTO assets (ip, mac, vendor, hostname, os_name, os_accuracy, first_seen, last_seen)
VALUES (:ip, :mac, :vendor, :hostname, :os_name, :os_accuracy, :seen, :seen)
ON CONFLICT(ip) DO UPDATE SET
    mac         = excluded.mac,
    vendor      = excluded.vendor,
    hostname    = excluded.hostname,
    os_name     = excluded.os_name,
    os_accuracy = excluded.os_accuracy,
    first_seen  = MIN(first_seen, excluded.first_seen),
    last_seen   = MAX(last_seen, excluded.last_seen)
"""

SERVICE_UPSERT = """
INSERT INTO services (ip, port, protocol, state, name, product, version, extra_info,
                      first_seen, last_seen)
VALUES (:ip, :port, :protocol, :state, :name, :product, :version, :extra_info,
        :seen, :seen)
ON CONFLICT(ip, port, protocol) DO UPDATE SET
    state      = excluded.state,
    name       = excluded.name,
    product    = excluded.product,
    version    = excluded.version,
    extra_info = excluded.extra_info,
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen  = MAX(last_seen, excluded.last_seen)
"""


def save_results(con, scan_time, hosts):
    """Upsert hosts and their open services in a single transaction."""
    with con:
        for host in hosts:
            con.execute(ASSET_UPSERT, {**host, "seen": scan_time})
            for service in host["services"]:
                con.execute(SERVICE_UPSERT, {**service, "ip": host["ip"], "seen": scan_time})


def main():
    parser = argparse.ArgumentParser(description="Load Nmap XML results into SQLite.")
    parser.add_argument("xml_files", nargs="+", help="Nmap XML file(s) to load")
    parser.add_argument("--db", default="asm.db", help="SQLite database path (default: asm.db)")
    args = parser.parse_args()

    con = connect(args.db)
    for path in args.xml_files:
        scan_time, hosts = parse_scan(path)
        save_results(con, scan_time, hosts)
        service_count = sum(len(host["services"]) for host in hosts)
        print(f"{path}: {len(hosts)} hosts up, {service_count} open services "
              f"(scan started {scan_time})")
    con.close()


if __name__ == "__main__":
    main()