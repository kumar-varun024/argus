import pytest

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.runtime.mission import Mission


def test_build_from_evidence_subdomain_takeover():
    store = EvidenceStore()
    ev = Evidence(
        category="subdomain_takeover",
        severity="critical",
        title="Subdomain Takeover on blog.example.com",
        value="blog.example.com",
        metadata={
            "subdomain": "blog.example.com",
            "cname": "blog.github.io",
            "service": "GitHub Pages",
            "template_id": "subdomain-takeover-github-pages",
        },
    )
    store.add(ev)

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence(store, target="example.com")

    # Check nodes
    sub_node = graph.get("subdomain:blog.example.com")
    assert sub_node is not None
    assert sub_node.type == "subdomain"

    vuln_node = graph.get("vulnerability:subdomain-takeover-github-pages:blog.example.com")
    assert vuln_node is not None
    assert vuln_node.type == "vulnerability"
    assert vuln_node.metadata["service"] == "GitHub Pages"

    cname_node = graph.get("cname:blog.github.io")
    assert cname_node is not None
    assert cname_node.type == "cname"

    # Check edges
    has_vuln_edge = False
    points_cname_edge = False
    for edge in graph.edges:
        if edge.source == "subdomain:blog.example.com" and edge.target == vuln_node.id and edge.type == "HAS_VULNERABILITY":
            has_vuln_edge = True
        if edge.source == "subdomain:blog.example.com" and edge.target == "cname:blog.github.io" and edge.type == "POINTS_TO_CNAME":
            points_cname_edge = True

    assert has_vuln_edge is True
    assert points_cname_edge is True


def test_build_mission_with_subdomain_takeover_vulnerabilities():
    mission = Mission(target="target.org")
    mission.subdomains = ["store.target.org"]
    mission.vulnerabilities = [
        {
            "name": "Subdomain Takeover (Shopify)",
            "template_id": "subdomain-takeover-shopify",
            "severity": "critical",
            "host": "store.target.org",
            "cname": "shops.myshopify.com",
            "service": "Shopify",
        }
    ]

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build(mission)

    sub_node = graph.get("subdomain:store.target.org")
    assert sub_node is not None

    vuln_node = graph.get("vulnerability:subdomain-takeover-shopify")
    assert vuln_node is not None
    assert vuln_node.metadata["service"] == "Shopify"

    has_vuln_edge = any(
        e.source == "subdomain:store.target.org" and e.target == "vulnerability:subdomain-takeover-shopify" and e.type == "HAS_VULNERABILITY"
        for e in graph.edges
    )
    assert has_vuln_edge is True
