"""build_from_evidence characterization scenarios: broad sweep (one shared
graph, one representative evidence item per category 2-29 in section order,
mirroring a real single-mission run) plus isolated edge cases for the
bespoke sections and the shared resolve_lh helper.

Sections 9,11,13-29 are structurally identical "generic vulnerability block"
copies -- their literal category lists/defaults are pinned separately by
fingerprint (see the Phase 6 attack_surface PR description); this suite only
needs to prove the *shared* control flow once via path_traversal, plus
XSS's one genuine quirk (severity mapping).
"""
from __future__ import annotations

from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from tests.graph.attackSurfaceScenarioHelpers import ev, graphSnapshot


def buildBroadSweepStore() -> EvidenceStore:
    store = EvidenceStore()
    store.add(ev("subdomain", value="www.example.com", source="subfinder"))
    store.add(ev("subdomain", metadata={"hostname": "example.com"}))
    store.add(ev("live_host", metadata={"url": "https://www.example.com", "host": "www.example.com", "technologies": "nginx, php"}))
    store.add(ev("live_host", metadata={"url": "https://api.example.com", "technologies": ["Express"]}))
    store.add(ev("technology", metadata={"name": "Apache", "url": "https://www.example.com"}))
    store.add(ev("endpoint", metadata={"url": "https://www.example.com/login"}))
    store.add(ev("vulnerability", metadata={"template_id": "generic-1", "host": "www.example.com"}, severity="high"))
    store.add(ev("subdomain_takeover", metadata={"subdomain": "old.example.com", "cname": "svc.herokudns.com", "service": "Heroku"}))
    store.add(ev("information_disclosure", metadata={
        "url": "https://www.example.com/.git/config", "host": "https://www.example.com", "path": "/.git/config",
        "secrets": [{"type": "api_key", "value": "abcd"}, "raw-secret"],
        "internal_domains": ["internal.corp.local"],
    }, title="Git Config Exposure"))
    store.add(ev("broken_access_control", metadata={"url": "https://www.example.com/admin/1"}))
    store.add(ev("path_traversal", metadata={"url": "https://www.example.com/download?f=../../etc/passwd"}))
    store.add(ev("sql_injection", metadata={"url": "https://www.example.com/search", "parameter": "q"}))
    store.add(ev("xss", metadata={"url": "https://www.example.com/comment", "parameter": "msg", "xss_type": "stored"}))
    store.add(ev("command_injection", metadata={"url": "https://api.example.com/ping", "parameter": "host"}))
    store.add(ev("ssrf", metadata={"url": "https://api.example.com/fetch", "parameter": "url"}))
    store.add(ev("oauth", metadata={"url": "https://www.example.com/oauth/callback"}))
    store.add(ev("xml_parser_validation", metadata={"url": "https://api.example.com/xml"}))
    store.add(ev("deserialization", metadata={"url": "https://api.example.com/load"}))
    store.add(ev("graphql", metadata={"url": "https://api.example.com/graphql"}))
    store.add(ev("websocket", metadata={"url": "https://api.example.com/ws"}))
    store.add(ev("request_smuggling", metadata={"url": "https://www.example.com/"}))
    store.add(ev("race_condition", metadata={"url": "https://api.example.com/redeem"}))
    store.add(ev("business_logic", metadata={"url": "https://api.example.com/checkout"}))
    store.add(ev("ssti", metadata={"url": "https://www.example.com/render", "parameter": "template"}))
    store.add(ev("cache_security", metadata={"url": "https://www.example.com/"}))
    store.add(ev("cors", metadata={"url": "https://api.example.com/data"}))
    store.add(ev("file_upload", metadata={"url": "https://www.example.com/upload", "filename": "shell.php.jpg"}))
    store.add(ev("api_security", metadata={"url": "https://api.example.com/users/1"}))
    store.add(ev("auth_bypass", metadata={"url": "https://www.example.com/login"}))
    store.add(ev("prototype_pollution", metadata={"url": "https://api.example.com/merge"}))
    return store


def _runBroadSweep(builder, results):
    graph = builder.build_from_evidence(buildBroadSweepStore(), target="example.com")
    results["broad_sweep"] = graphSnapshot(graph)


def _runLiveHostElifBranches(builder, results):
    store = EvidenceStore()
    store.add(ev("live_host", value="standalone-nohost"))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::live_host_elif_no_prior_subdomain"] = graphSnapshot(graph)

    store2 = EvidenceStore()
    store2.add(ev("subdomain", value="example.com"))
    store2.add(ev("live_host", value="standalone-nohost"))
    graph2 = builder.build_from_evidence(store2, target="example.com")
    results["edge::live_host_elif_with_prior_subdomain"] = graphSnapshot(graph2)


def _runTechnologyEdgeCases(builder, results):
    store = EvidenceStore()
    store.add(ev("technology", metadata={"name": "Redis", "url": "https://unmatched.example.com"}))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::technology_unresolved_live_host"] = graphSnapshot(graph)

    # metadata non-empty but lacks "name": exercises the `if "name" not in tech_meta` assign.
    store2 = EvidenceStore()
    store2.add(ev("technology", value="Redis", metadata={"source_note": "banner-grab"}))
    graph2 = builder.build_from_evidence(store2, target="example.com")
    results["edge::technology_missing_name_key"] = graphSnapshot(graph2)


def _runEndpointMissingUrlKey(builder, results):
    # metadata non-empty but lacks "url": exercises the `if url and "url" not in ep_meta` assign.
    store = EvidenceStore()
    store.add(ev("endpoint", value="https://noturlkey.example.com/path", metadata={"host": "noturlkey.example.com"}))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::endpoint_missing_url_key"] = graphSnapshot(graph)


def _runVulnerabilityEdgeCases(builder, results):
    store = EvidenceStore()
    store.add(ev("vulnerability", metadata={"template_id": "generic-2", "matched_at": "www.example.com"}))
    store.add(ev("vulnerability", metadata={"template_id": "generic-3", "host": "www.example.com", "severity": "low"}, severity="critical"))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::vulnerability_matched_at_and_severity_preset"] = graphSnapshot(graph)


def _runSubdomainTakeoverEdgeCases(builder, results):
    store = EvidenceStore()
    store.add(ev("subdomain", value="already.example.com"))
    store.add(ev("subdomain_takeover", value="fallback-value-only"))
    store.add(ev("subdomain_takeover", metadata={"subdomain": "already.example.com"}))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::subdomain_takeover_minimal_and_existing"] = graphSnapshot(graph)


def _runInformationDisclosureEdgeCases(builder, results):
    store = EvidenceStore()
    store.add(ev("information_disclosure", metadata={"path": "/config.yml"}, value="https://solo.example.com/config.yml"))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::information_disclosure_no_live_hosts"] = graphSnapshot(graph)

    store2 = EvidenceStore()
    store2.add(ev("live_host", metadata={"url": "https://only.example.com"}))
    store2.add(ev("information_disclosure", metadata={"path": "/secret"}, value="https://different.example.com/secret"))
    graph2 = builder.build_from_evidence(store2, target="example.com")
    results["edge::information_disclosure_single_live_host_fallback"] = graphSnapshot(graph2)

    # direct graph.get(f"live_host:{base_url}") misses (id keyed by full url), but the
    # nodes_by_type("live_host") loop matches via metadata.host == base_url.
    store3 = EvidenceStore()
    store3.add(ev("live_host", metadata={"url": "https://foo.example.com", "host": "bare-host.example.com"}))
    store3.add(ev("live_host", metadata={"url": "https://second.example.com"}))
    store3.add(ev("information_disclosure", metadata={"path": "/x", "host": "bare-host.example.com"}, value="https://foo.example.com/x"))
    graph3 = builder.build_from_evidence(store3, target="example.com")
    results["edge::information_disclosure_loop_fallback_match"] = graphSnapshot(graph3)


def _runResolveLhFuzzyFallbacks(builder, results):
    # Exercises resolve_lh's fuzzy-match fallback branches: netloc/hostname lookup,
    # substring prefix loops (both target_url_val and host_val arms), and the final
    # len(live_hosts_list) == 1 fallback (called with neither url nor host).
    store = EvidenceStore()
    store.add(ev("live_host", metadata={"url": "https://fuzzy.example.com/base", "host": "fuzzy.example.com"}))
    store.add(ev("sql_injection", metadata={"url": "https://fuzzy.example.com/base/deep/path", "parameter": "id"}))
    store.add(ev("broken_access_control", metadata={"host": "sub.fuzzy.example.com"}))
    graph = builder.build_from_evidence(store, target="example.com")
    results["edge::resolve_lh_fuzzy_fallbacks"] = graphSnapshot(graph)

    store2 = EvidenceStore()
    store2.add(ev("live_host", metadata={"url": "https://solo.example.com"}))
    store2.add(ev("technology", metadata={"name": "Nginx"}))
    graph2 = builder.build_from_evidence(store2, target="example.com")
    results["edge::resolve_lh_single_host_fallback"] = graphSnapshot(graph2)

    store3 = EvidenceStore()
    store3.add(ev("live_host", metadata={"url": "https://trailingslash.example.com/"}))
    store3.add(ev("broken_access_control", metadata={"host": "https://trailingslash.example.com"}))
    graph3 = builder.build_from_evidence(store3, target="example.com")
    results["edge::resolve_lh_host_val_rstripped_url_match"] = graphSnapshot(graph3)

    store4 = EvidenceStore()
    store4.add(ev("live_host", metadata={"host": "parsedhost.example.com", "url": "https://parsedhost.example.com/app"}))
    store4.add(ev("path_traversal", metadata={"host": "https://parsedhost.example.com:9443/ignored"}))
    graph4 = builder.build_from_evidence(store4, target="example.com")
    results["edge::resolve_lh_host_val_parsed_hostname_match"] = graphSnapshot(graph4)

    store5 = EvidenceStore()
    store5.add(ev("live_host", metadata={"url": "https://my-real-host.example.com/x"}))
    store5.add(ev("broken_access_control", metadata={"host": "https://real-host.example.com:443/y"}))
    graph5 = builder.build_from_evidence(store5, target="example.com")
    results["edge::resolve_lh_host_val_containment_loop_match"] = graphSnapshot(graph5)

    store6 = EvidenceStore()
    store6.add(ev("live_host", metadata={"host": "directmatch.example.com", "url": "https://directmatch.example.com/x"}))
    store6.add(ev("broken_access_control", metadata={"host": "directmatch.example.com"}))
    graph6 = builder.build_from_evidence(store6, target="example.com")
    results["edge::resolve_lh_host_val_exact_lh_by_host_match"] = graphSnapshot(graph6)

    store7 = EvidenceStore()
    store7.add(ev("live_host", metadata={"url": "https://portendpoint.example.com/app"}))
    store7.add(ev("command_injection", metadata={"url": "https://portendpoint.example.com:8443/other/path"}))
    graph7 = builder.build_from_evidence(store7, target="example.com")
    results["edge::resolve_lh_target_url_hostname_vs_netloc"] = graphSnapshot(graph7)

    store8 = EvidenceStore()
    store8.add(ev("live_host", metadata={"host": "customkey123"}))
    store8.add(ev("ssrf", metadata={"url": "customkey123-suffix-path-more-stuff"}))
    graph8 = builder.build_from_evidence(store8, target="example.com")
    results["edge::resolve_lh_target_url_prefix_loop_only"] = graphSnapshot(graph8)


PATH_TRAVERSAL_SCENARIOS = [
    ("resolves_existing_live_host", [
        ("live_host", {"url": "https://target.example.com"}),
        ("path_traversal", {"url": "https://target.example.com/file?f=../etc/passwd", "parameter": "f"}),
    ]),
    ("creates_new_live_host", [
        ("path_traversal", {"url": "https://newhost.example.com/file?f=../etc/passwd", "parameter": "f"}),
    ]),
    ("no_target_url", [("path_traversal", {})]),
]

XSS_SCENARIOS = [
    ("stored_default_critical", {"xss_type": "stored", "url": "https://example.com/x"}, "info"),
    ("dom_default_medium", {"xss_type": "dom_based", "url": "https://example.com/x"}, "info"),
    ("header_default_medium", {"xss_type": "header_injection", "url": "https://example.com/x"}, "info"),
    ("reflected_default_high", {"xss_type": "reflected", "url": "https://example.com/x"}, "info"),
    ("unknown_type_default_high", {"url": "https://example.com/x"}, "info"),
    ("explicit_non_info_severity_kept", {"xss_type": "reflected", "url": "https://example.com/x"}, "low"),
    ("metadata_severity_info_overridden", {"xss_type": "stored", "url": "https://example.com/x", "severity": "info"}, "info"),
    ("cross_site_scripting_alias", {"url": "https://example.com/x"}, "info"),
]


def _runPathTraversalDeepDive(builder, results):
    for name, items in PATH_TRAVERSAL_SCENARIOS:
        store = EvidenceStore()
        for category, metadata in items:
            store.add(ev(category, metadata=metadata))
        graph = builder.build_from_evidence(store, target="example.com")
        results[f"edge::path_traversal_{name}"] = graphSnapshot(graph)


def _runXssSeverityMapping(builder, results):
    for name, metadata, evSeverity in XSS_SCENARIOS:
        store = EvidenceStore()
        category = "cross_site_scripting" if name == "cross_site_scripting_alias" else "xss"
        store.add(ev(category, metadata=metadata, severity=evSeverity))
        graph = builder.build_from_evidence(store, target="example.com")
        results[f"edge::xss_{name}"] = graphSnapshot(graph)


def _runEmptyAndNoTargetEdgeCases(builder, results):
    graph = builder.build_from_evidence(EvidenceStore(), target="")
    results["edge::empty_store_no_target"] = graphSnapshot(graph)
    graph2 = builder.build_from_evidence(None, target="example.com")
    results["edge::none_evidence"] = graphSnapshot(graph2)
    existing = KnowledgeGraph()
    graph3 = builder.build_from_evidence(EvidenceStore(), target="example.com", graph=existing)
    results["edge::preexisting_graph_reused"] = graphSnapshot(graph3)
    assert graph3 is existing


def runAll(builder, results):
    _runBroadSweep(builder, results)
    _runLiveHostElifBranches(builder, results)
    _runTechnologyEdgeCases(builder, results)
    _runEndpointMissingUrlKey(builder, results)
    _runVulnerabilityEdgeCases(builder, results)
    _runSubdomainTakeoverEdgeCases(builder, results)
    _runInformationDisclosureEdgeCases(builder, results)
    _runResolveLhFuzzyFallbacks(builder, results)
    _runPathTraversalDeepDive(builder, results)
    _runXssSeverityMapping(builder, results)
    _runEmptyAndNoTargetEdgeCases(builder, results)
