from __future__ import annotations

import pytest
from argus.reporting.cvss import CVSSCalculator, cvss_roundup
from argus.reporting.models import ReportSeverity


def test_cvss_roundup():
    assert cvss_roundup(4.0) == 4.0
    assert cvss_roundup(4.00000) == 4.0
    assert cvss_roundup(4.01) == 4.1
    assert cvss_roundup(4.02) == 4.1
    assert cvss_roundup(9.76035875) == 9.8
    assert cvss_roundup(6.0054) == 6.1
    assert cvss_roundup(0.0) == 0.0


def test_cvss_official_vectors():
    # 1. Critical standard RCE (9.8)
    v1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert CVSSCalculator.calculate_base_score(v1) == 9.8

    # 2. Critical scope changed (10.0)
    v2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert CVSSCalculator.calculate_base_score(v2) == 10.0

    # 3. High authenticated IDOR (8.8)
    v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert CVSSCalculator.calculate_base_score(v3) == 8.8

    # 4. Medium Reflected XSS (6.1)
    v4 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert CVSSCalculator.calculate_base_score(v4) == 6.1

    # 5. Medium Low Impact Info Leak (5.3)
    v5 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert CVSSCalculator.calculate_base_score(v5) == 5.3

    # 6. Low (3.1)
    v6 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    assert CVSSCalculator.calculate_base_score(v6) == 3.1

    # 7. Info / None (0.0)
    v7 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert CVSSCalculator.calculate_base_score(v7) == 0.0


def test_parse_and_format_vector():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    metrics = CVSSCalculator.parse_vector(vec)
    assert metrics["AV"] == "N"
    assert metrics["AC"] == "L"
    assert metrics["PR"] == "N"
    assert metrics["UI"] == "N"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"
    assert metrics["I"] == "H"
    assert metrics["A"] == "H"

    rebuilt = CVSSCalculator.format_vector(metrics)
    assert rebuilt == vec


def test_score_to_severity_bands():
    assert CVSSCalculator.score_to_severity(0.0) == ReportSeverity.INFO
    assert CVSSCalculator.score_to_severity(0.1) == ReportSeverity.LOW
    assert CVSSCalculator.score_to_severity(3.9) == ReportSeverity.LOW
    assert CVSSCalculator.score_to_severity(4.0) == ReportSeverity.MEDIUM
    assert CVSSCalculator.score_to_severity(6.9) == ReportSeverity.MEDIUM
    assert CVSSCalculator.score_to_severity(7.0) == ReportSeverity.HIGH
    assert CVSSCalculator.score_to_severity(8.9) == ReportSeverity.HIGH
    assert CVSSCalculator.score_to_severity(9.0) == ReportSeverity.CRITICAL
    assert CVSSCalculator.score_to_severity(10.0) == ReportSeverity.CRITICAL


def test_get_approximate_cvss_severity_ranges():
    # Critical must be >= 9.0 (9.0–10.0)
    crit = CVSSCalculator.get_approximate_cvss("command_injection", "critical")
    assert crit.score >= 9.0
    assert crit.score <= 10.0
    assert crit.severity_rating == "Critical"

    # High must be 7.0–8.9
    high = CVSSCalculator.get_approximate_cvss("broken_access_control", "high")
    assert high.score >= 7.0
    assert high.score <= 8.9
    assert high.severity_rating == "High"

    # Medium must be 4.0–6.9
    med = CVSSCalculator.get_approximate_cvss("reflected_xss", "medium")
    assert med.score >= 4.0
    assert med.score <= 6.9
    assert med.severity_rating == "Medium"

    # Low must be 0.1–3.9
    low = CVSSCalculator.get_approximate_cvss("open_redirect", "low")
    assert low.score >= 0.1
    assert low.score <= 3.9
    assert low.severity_rating == "Low"

    # Info must be 0.0
    info = CVSSCalculator.get_approximate_cvss("recon", "info")
    assert info.score == 0.0
    assert info.severity_rating == "None"


def test_get_approximate_cvss_with_metadata_override():
    # Direct vector in metadata
    meta_vec = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}
    res_vec = CVSSCalculator.get_approximate_cvss("xss", "high", metadata=meta_vec)
    assert res_vec.score == 6.1
    assert res_vec.severity_rating == "Medium"

    # Direct score in metadata
    meta_score = {"cvss_score": 8.5}
    res_score = CVSSCalculator.get_approximate_cvss("sqli", metadata=meta_score)
    assert res_score.score == 8.5
    assert res_score.severity_rating == "High"


def test_cwe_resolution():
    cwe_sqli = CVSSCalculator.get_cwe_for_category("sql_injection")
    assert cwe_sqli is not None
    assert cwe_sqli.id == "CWE-89"

    cwe_xss = CVSSCalculator.get_cwe_for_category("xss")
    assert cwe_xss is not None
    assert cwe_xss.id == "CWE-79"

    cwe_rce = CVSSCalculator.get_cwe_for_category("command_injection")
    assert cwe_rce is not None
    assert cwe_rce.id == "CWE-78"

    # Custom CWE in metadata
    custom_cwe = CVSSCalculator.get_cwe_for_category("custom", metadata={"cwe_id": "CWE-999", "cwe_name": "Custom Flaw"})
    assert custom_cwe is not None
    assert custom_cwe.id == "CWE-999"
    assert custom_cwe.name == "Custom Flaw"
