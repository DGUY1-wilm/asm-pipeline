from pathlib import Path

from src.asm.parse_openvas import parse_report

FIXTURE = Path(__file__).parent / "fixtures" / "openvas_sample.xml"


def test_counts_only_main_results_not_nested_or_summary_entries():
    _, total, _ = parse_report(FIXTURE)
    assert total == 2


def test_log_results_are_not_stored_as_findings():
    _, _, findings = parse_report(FIXTURE)
    assert len(findings) == 1


def test_finding_fields_are_extracted():
    scan_time, _, findings = parse_report(FIXTURE)
    finding = findings[0]
    assert scan_time == "2026-01-15T10:00:00Z"
    assert finding["ip"] == "192.0.2.10"
    assert finding["port"] == "21/tcp"
    assert finding["severity"] == 9.8
    assert finding["qod"] == 99
    assert finding["solution"] == "Remove the backdoored package."


def test_only_cve_references_are_kept():
    _, _, findings = parse_report(FIXTURE)
    assert findings[0]["cves"] == "CVE-2011-2523"