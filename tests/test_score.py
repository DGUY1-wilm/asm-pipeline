from src.asm.score import due_date, score_finding


def make_finding(severity, cves=None, name="Example finding"):
    return {"name": name, "severity": severity, "cves": cves}


def test_kev_listed_cve_is_p1_even_with_lower_cvss():
    priority, _, in_kev, _, _ = score_finding(make_finding(7.5, "CVE-A"), {"CVE-A": "Unknown"}, {})
    assert priority == "P1"
    assert in_kev is True


def test_critical_with_likely_exploitation_is_p1():
    priority, *_ = score_finding(make_finding(9.8, "CVE-B"), {}, {"CVE-B": 0.6})
    assert priority == "P1"


def test_critical_without_exploitation_evidence_is_p2():
    priority, *_ = score_finding(make_finding(9.8, "CVE-C"), {}, {"CVE-C": 0.01})
    assert priority == "P2"


def test_backdoor_without_cve_is_p1_and_sorts_at_the_top():
    finding = make_finding(10.0, None, "Possible Backdoor: Ingreslock")
    priority, sort_score, _, max_epss, reason = score_finding(finding, {}, {})
    assert priority == "P1"
    assert sort_score == 1.0
    assert max_epss is None
    assert "no CVE" in reason


def test_high_epss_alone_does_not_make_a_low_impact_finding_urgent():
    priority, *_ = score_finding(make_finding(4.3, "CVE-POODLE"), {}, {"CVE-POODLE": 1.0})
    assert priority == "P3"


def test_worst_case_epss_is_used_across_cves():
    _, _, _, max_epss, _ = score_finding(
        make_finding(9.0, "CVE-1,CVE-2"), {}, {"CVE-1": 0.05, "CVE-2": 0.9}
    )
    assert max_epss == 0.9


def test_sort_score_is_capped_at_one():
    _, sort_score, *_ = score_finding(
        make_finding(10.0, "CVE-R"), {"CVE-R": "Known"}, {"CVE-R": 1.0}
    )
    assert sort_score == 1.0


def test_due_date_counts_from_first_seen():
    assert due_date("2026-10-22T18:06:51Z", 7) == "2026-10-29"