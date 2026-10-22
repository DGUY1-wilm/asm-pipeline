"""Launch an OpenVAS (GVM) scan through the GMP API and save the report as XML.

Usage (from the project root):
    python3 -m src.asm.openvas_scan 192.168.56.105
"""
import argparse
import getpass
import ipaddress
import os
import time
from datetime import datetime, timezone

from gvm.connections import UnixSocketConnection
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

try:
    from gvm.protocols.gmp import GMP
except ImportError:  # older python-gvm versions name the class Gmp
    from gvm.protocols.gmp import Gmp as GMP

SOCKET_PATH = "/run/gvmd/gvmd.sock"
LAB_NETWORK = ipaddress.ip_network("192.168.56.0/24")
SCAN_CONFIG = "Full and fast"
PORT_LIST = "All IANA assigned TCP"
SCANNER = "OpenVAS Default"
POLL_SECONDS = 30


def find_id(response, tag, name):
    """Return the id of the first <tag> element whose <name> matches."""
    for element in response.findall(tag):
        if element.findtext("name") == name:
            return element.get("id")
    raise SystemExit(f"Could not find a {tag} named '{name}'")


def wait_for_task(gmp, task_id):
    """Poll the task until it finishes, printing progress."""
    while True:
        task = gmp.get_task(task_id).find("task")
        status = task.findtext("status")
        progress = task.findtext("progress")
        print(f"  status: {status}, progress: {progress}%")
        if status == "Done":
            return
        if status in ("Stopped", "Interrupted"):
            raise SystemExit(f"Scan ended with status: {status}")
        time.sleep(POLL_SECONDS)


def main():
    parser = argparse.ArgumentParser(description="Run an OpenVAS scan and save the XML report.")
    parser.add_argument("target", help="IP address to scan (lab network only)")
    parser.add_argument("--user", default="admin", help="GVM username (default: admin)")
    parser.add_argument("--out-dir", default="scans", help="Where to save the report")
    args = parser.parse_args()

    # Scope guard: refuse to scan anything outside the isolated lab network.
    if ipaddress.ip_address(args.target) not in LAB_NETWORK:
        raise SystemExit(f"{args.target} is outside {LAB_NETWORK}; refusing to scan.")

    password = os.environ.get("GVM_PASSWORD") or getpass.getpass(f"GVM password for {args.user}: ")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    connection = UnixSocketConnection(path=SOCKET_PATH, timeout=300)
    with GMP(connection, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(args.user, password)

        config_id = find_id(gmp.get_scan_configs(filter_string="rows=-1"), "config", SCAN_CONFIG)
        port_list_id = find_id(gmp.get_port_lists(filter_string="rows=-1"), "port_list", PORT_LIST)
        scanner_id = find_id(gmp.get_scanners(filter_string="rows=-1"), "scanner", SCANNER)

        target_id = gmp.create_target(
            name=f"{args.target} {stamp}", hosts=[args.target], port_list_id=port_list_id
        ).get("id")
        task_id = gmp.create_task(
            name=f"Scan {args.target} {stamp}",
            config_id=config_id, target_id=target_id, scanner_id=scanner_id,
        ).get("id")
        report_id = gmp.start_task(task_id).findtext("report_id")
        print(f"Started task {task_id} (report {report_id})")

        wait_for_task(gmp, task_id)

        report = gmp.get_report(
            report_id,
            filter_string="apply_overrides=0 min_qod=70 rows=-1",
            ignore_pagination=True,
            details=True,
        )

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"openvas_{args.target}_{stamp}.xml")
    with open(out_path, "wb") as f:
        f.write(etree.tostring(report, pretty_print=True))
    print(f"Saved report to {out_path}")


if __name__ == "__main__":
    main()