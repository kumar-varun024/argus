import pytest
from unittest.mock import MagicMock

from argus.recon.takeover_fingerprints import (
    TakeoverSignature,
    TAKEOVER_SIGNATURES,
    find_signature_by_cname,
    find_signature_by_service,
    get_all_signatures,
)
from argus.collectors.takeover import SubdomainTakeoverCollector
from argus.runtime.mission import Mission
from argus.tools.dnsx import DNSXTool, DNSResult


def test_takeover_signature_matches_cname():
    sig = TakeoverSignature(
        service="GitHub Pages",
        cname_patterns=["github.io", "github.map.fastly.net"],
        fingerprints=["There isn't a GitHub Pages site here."],
    )
    assert sig.matches_cname("user.github.io") is True
    assert sig.matches_cname("foo.github.map.fastly.net") is True
    assert sig.matches_cname("unrelated.amazonaws.com") is False
    assert sig.matches_cname("") is False


def test_takeover_signature_matches_body():
    sig = TakeoverSignature(
        service="AWS S3",
        cname_patterns=["s3.amazonaws.com"],
        fingerprints=["The specified bucket does not exist", "NoSuchBucket"],
    )
    assert sig.matches_body("<Error><Code>NoSuchBucket</Code></Error>") is True
    assert sig.matches_body("Welcome to our company website") is False
    assert sig.matches_body("") is False


def test_takeover_signature_matches_status():
    sig = TakeoverSignature(
        service="Heroku",
        cname_patterns=["herokuapp.com"],
        status_codes=[404, 502, 503],
    )
    assert sig.matches_status(404) is True
    assert sig.matches_status(502) is True
    assert sig.matches_status(200) is False


def test_database_has_minimum_20_signatures():
    signatures = get_all_signatures()
    assert len(signatures) >= 20
    services = [s.service.lower() for s in signatures]
    required_services = [
        "github pages",
        "aws s3",
        "heroku",
        "azure app service",
        "aws cloudfront",
        "shopify",
        "fastly",
        "pantheon",
        "helpjuice",
        "surge.sh",
        "tumblr",
        "wordpress.com",
        "ghost",
        "cargo collective",
        "bitbucket",
        "feedpress",
        "readme.io",
        "statuspage",
        "zendesk",
        "webflow",
        "strikingly",
        "unbounce",
        "hubspot",
        "fly.io",
        "vercel",
        "netlify",
    ]
    for req in required_services:
        assert req in services, f"Missing required takeover service: {req}"


def test_find_signature_by_cname_and_service():
    gh_sigs = find_signature_by_cname("myblog.github.io")
    assert len(gh_sigs) > 0
    assert gh_sigs[0].service == "GitHub Pages"

    s3_sig = find_signature_by_service("AWS S3")
    assert s3_sig is not None
    assert s3_sig.service == "AWS S3"

    unknown = find_signature_by_service("NonExistentService123")
    assert unknown is None


def test_collector_github_pages_takeover_detected():
    mission = Mission(target="example.com")
    mission.subdomains = ["pages.example.com"]

    mock_dns = MagicMock(spec=DNSXTool)
    mock_dns.resolve.return_value = [
        DNSResult(
            host="pages.example.com",
            cname=["user.github.io"],
            status_code="NOERROR",
        )
    ]

    collector = SubdomainTakeoverCollector(dns_tool=mock_dns)
    # Mock HTTP probing
    collector._probe_http = MagicMock(return_value=(404, "404 Not Found - There isn't a GitHub Pages site here"))

    evidence = collector.collect(mission)

    assert len(evidence) == 1
    assert evidence[0].category == "subdomain_takeover"
    assert evidence[0].severity == "critical"
    assert "GitHub Pages" in evidence[0].title
    assert evidence[0].metadata["subdomain"] == "pages.example.com"
    assert evidence[0].metadata["cname"] == "user.github.io"
    assert len(mission.vulnerabilities) == 1
    assert mission.vulnerabilities[0]["service"] == "GitHub Pages"


def test_collector_s3_takeover_detected():
    mission = Mission(target="company.com")
    mission.subdomains = ["assets.company.com"]

    mock_dns = MagicMock(spec=DNSXTool)
    mock_dns.resolve.return_value = [
        DNSResult(
            host="assets.company.com",
            cname=["assets.company.com.s3.amazonaws.com"],
            status_code="NOERROR",
        )
    ]

    collector = SubdomainTakeoverCollector(dns_tool=mock_dns)
    collector._probe_http = MagicMock(return_value=(404, "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"))

    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert evidence[0].metadata["service"] == "AWS S3"


def test_collector_nxdomain_takeover_detected():
    custom_sig = TakeoverSignature(
        service="CustomNXService",
        cname_patterns=["customnx.io"],
        nxdomain=True,
    )
    mission = Mission(target="test.org")
    mission.subdomains = ["staging.test.org"]

    mock_dns = MagicMock(spec=DNSXTool)
    mock_dns.resolve.return_value = [
        DNSResult(
            host="staging.test.org",
            cname=["unclaimed.customnx.io"],
            status_code="NXDOMAIN",
        )
    ]

    collector = SubdomainTakeoverCollector(dns_tool=mock_dns, signatures=[custom_sig])
    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert evidence[0].metadata["service"] == "CustomNXService"
    assert evidence[0].metadata["fingerprint_matched"] == "NXDOMAIN status"


def test_collector_non_vulnerable_subdomain_ignored():
    mission = Mission(target="example.com")
    mission.subdomains = ["secure.example.com"]

    mock_dns = MagicMock(spec=DNSXTool)
    mock_dns.resolve.return_value = [
        DNSResult(
            host="secure.example.com",
            cname=["live.github.io"],
            status_code="NOERROR",
        )
    ]

    collector = SubdomainTakeoverCollector(dns_tool=mock_dns)
    # Healthy page returned, no error fingerprint
    collector._probe_http = MagicMock(return_value=(200, "<html>Welcome to my active project!</html>"))

    evidence = collector.collect(mission)
    assert len(evidence) == 0
    assert len(mission.vulnerabilities) == 0


def test_collector_empty_subdomains_falls_back_to_target():
    mission = Mission(target="myblog.github.io")
    mission.subdomains = []

    mock_dns = MagicMock(spec=DNSXTool)
    mock_dns.resolve.return_value = [
        DNSResult(
            host="myblog.github.io",
            cname=["myblog.github.io"],
            status_code="NOERROR",
        )
    ]

    collector = SubdomainTakeoverCollector(dns_tool=mock_dns)
    collector._probe_http = MagicMock(return_value=(404, "There isn't a GitHub Pages site here."))

    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert evidence[0].value == "myblog.github.io"
