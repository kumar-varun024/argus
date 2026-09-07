"""build() characterization scenarios: the Mission-attribute-direct
ingestion path (dict and non-dict item variants, evidence-present vs
absent), covering build()'s own distinct branches (not shared with
build_from_evidence).
"""
from __future__ import annotations

from tests.graph.attackSurfaceEvidenceScenarios import buildBroadSweepStore
from tests.graph.attackSurfaceScenarioHelpers import DictLikeMission, graphSnapshot


def _runBuildFromMissionDirect(builder, results):
    mission = DictLikeMission(
        target="mission.example.com",
        subdomains=[{"hostname": "www.mission.example.com"}, "bare-string-sub.mission.example.com"],
        live_hosts=[
            {"url": "https://www.mission.example.com", "host": "www.mission.example.com", "technologies": ["nginx"]},
            "https://bare-string-host.mission.example.com",
        ],
        technologies=[{"name": "PHP"}, "bare-tech-string"],
        endpoints=[{"url": "https://www.mission.example.com/api"}, "https://www.mission.example.com/other"],
        vulnerabilities=[
            {"template_id": "generic", "host": "www.mission.example.com", "url": "https://www.mission.example.com/api"},
            "bare-vuln-string",
        ],
    )
    graph = builder.build(mission)
    results["build::mission_direct_dict_and_bare_variants"] = graphSnapshot(graph)
    assert mission.attack_surface_graph is graph
    assert mission.graph is graph

    mission2 = DictLikeMission(target="withev.example.com", evidence=buildBroadSweepStore())
    graph2 = builder.build(mission2)
    results["build::mission_with_evidence_store"] = graphSnapshot(graph2)


def _runBuildLiveHostElifBranches(builder, results):
    # A dict live_host with neither "url" nor "host" keeps `host` falsy end-to-end
    # (unlike a bare string, whose url-derivation always falls back to the string
    # itself), which is what's needed to reach the `elif target:` branch at all.
    mission = DictLikeMission(
        target="build.example.com",
        subdomains=[{"hostname": "build.example.com"}],
        live_hosts=[{}],
    )
    graph = builder.build(mission)
    results["build::live_host_elif_with_prior_subdomain"] = graphSnapshot(graph)

    mission2 = DictLikeMission(target="build2.example.com", live_hosts=[{}])
    graph2 = builder.build(mission2)
    results["build::live_host_elif_no_prior_subdomain"] = graphSnapshot(graph2)


def _runBuildTechnologySingleLiveHostConnect(builder, results):
    mission = DictLikeMission(
        target="techsolo.example.com",
        live_hosts=[{"url": "https://techsolo.example.com"}],
        technologies=["Varnish"],
    )
    graph = builder.build(mission)
    results["build::technology_single_live_host_connect"] = graphSnapshot(graph)


def _runBuildEndpointFallbackLoops(builder, results):
    mission = DictLikeMission(
        target="epfallback.example.com",
        live_hosts=[{"url": "https://epfallback.example.com", "host": "epfallback.example.com"}],
        endpoints=[{"url": "https://different-prefix.example.com/api", "host": "epfallback.example.com"}],
    )
    graph = builder.build(mission)
    results["build::endpoint_fallback_host_match"] = graphSnapshot(graph)

    mission2 = DictLikeMission(
        target="epsolo.example.com",
        live_hosts=[{"url": "https://epsolo.example.com"}],
        endpoints=[{"url": "https://unrelated-prefix.example.com/api"}],
    )
    graph2 = builder.build(mission2)
    results["build::endpoint_single_live_host_fallback"] = graphSnapshot(graph2)


def _runBuildVulnerabilityEdgeCases(builder, results):
    mission = DictLikeMission(
        target="vulncname.example.com",
        subdomains=[{"hostname": "old.vulncname.example.com"}],
        vulnerabilities=[{
            "template_id": "takeover", "host": "old.vulncname.example.com",
            "cname": "svc.example-cdn.com", "service": "CDN",
        }],
    )
    graph = builder.build(mission)
    results["build::vulnerability_cname_existing_subdomain"] = graphSnapshot(graph)

    # First loop (startswith / exact-host) must miss, so vuln_host needs a scheme
    # (so its urlparse().hostname differs from the raw string) and must not match
    # the live host's own url/host via prefix or equality; the second loop then
    # matches via the *parsed* hostname equaling the live host's metadata host.
    mission2 = DictLikeMission(
        target="vulnfuzzy.example.com",
        live_hosts=[{"url": "https://vulnfuzzy.example.com/base", "host": "vulnfuzzy.example.com"}],
        vulnerabilities=[{"template_id": "generic", "host": "https://vulnfuzzy.example.com/some/other/path"}],
    )
    graph2 = builder.build(mission2)
    results["build::vulnerability_fuzzy_host_match"] = graphSnapshot(graph2)

    mission3 = DictLikeMission(
        target="vulnsolo.example.com",
        live_hosts=[{"url": "https://vulnsolo.example.com"}],
        vulnerabilities=[{"template_id": "generic", "host": "unrelated-host-not-matching.example.com"}],
    )
    graph3 = builder.build(mission3)
    results["build::vulnerability_single_live_host_fallback"] = graphSnapshot(graph3)

    mission4 = DictLikeMission(
        target="takeover.example.com",
        vulnerabilities=[{
            "template_id": "subdomain-takeover-heroku", "name": "Takeover", "host": "old.takeover.example.com",
            "cname": "svc.herokudns.com", "service": "Heroku",
        }],
    )
    graph4 = builder.build(mission4)
    results["build::mission_takeover_cname_direct"] = graphSnapshot(graph4)


def _runBuildAttachExceptionSwallowed(builder, results):
    class ImmutableMission:
        target = "immutable.example.com"

        def __setattr__(self, key, value):
            raise AttributeError("read-only mission")

    graph = builder.build(ImmutableMission())
    results["build::attach_exception_swallowed"] = graphSnapshot(graph)


def runAll(builder, results):
    _runBuildFromMissionDirect(builder, results)
    _runBuildLiveHostElifBranches(builder, results)
    _runBuildTechnologySingleLiveHostConnect(builder, results)
    _runBuildEndpointFallbackLoops(builder, results)
    _runBuildVulnerabilityEdgeCases(builder, results)
    _runBuildAttachExceptionSwallowed(builder, results)
