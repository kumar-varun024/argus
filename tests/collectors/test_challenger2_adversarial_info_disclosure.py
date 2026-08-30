"""
Challenger 2 Empirical Adversarial Stress Test Suite for Sprint 5:
Information Disclosure Engine, Attack Surface Expansion Graph Loop, and DAG Planning.
"""
import ssl
import pytest
from unittest.mock import MagicMock, patch
import httpx

from argus.collectors.information_disclosure import (
    InformationDisclosureCollector,
    SecretExtractor,
    DEFAULT_WORDLIST,
)
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.task_generator import TaskGenerator
from argus.planning.models import CoverageGap, TaskCategory, ResearchTask


class MockMission:
    def __init__(self, target="example.com"):
        self.id = "test-mission-challenger-2"
        self.target = target
        self.subdomains = []
        self.live_hosts = []
        self.endpoints = []
        self.technologies = []
        self.vulnerabilities = []
        self.evidence = EvidenceStore()
        self.attack_surface_graph = KnowledgeGraph()
        self.graph = self.attack_surface_graph
        self.tool_runs = {}
        self.execution_history = []
        self.task_states = {}
        self.research_tasks = []


class MockHttpResponse:
    def __init__(self, status_code=200, text="", raw_body=None, url=None, headers=None):
        self.status_code = status_code
        self.text = text
        self.raw_body = raw_body if raw_body is not None else text
        self.url = url or "https://example.com"
        self.headers = headers or {}


# ==============================================================================
# Scenario 1: Duplicate Domain Discoveries & Deduplication
# ==============================================================================

def test_duplicate_domain_discovery_deduplication_in_mission_and_graph():
    """Verify that multiple files leaking identical subdomains do not produce duplicate entries or broken graphs."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://app.example.com"]
    mission.subdomains = ["app.example.com"]

    # Injected client returns .env and .git/config with identical and mixed-cased subdomains
    def mock_get(mission_arg, url, **kwargs):
        if ".env" in url:
            return MockHttpResponse(
                status_code=200,
                text="DATABASE_URL=postgres://user:pass@db.internal.example.com:5432/prod\nAPI_HOST=api.example.com",
                url=url
            )
        elif ".git/config" in url:
            return MockHttpResponse(
                status_code=200,
                text='[remote "origin"]\n\turl = https://API.EXAMPLE.COM/repo.git\n[remote "backup"]\n\turl = https://db.internal.example.com/repo.git',
                url=url
            )
        return MockHttpResponse(status_code=404, text="Not Found", url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env", ".git/config"])
    evidence = collector.collect(mission)

    assert len(evidence) == 2
    # Verify mission.subdomains deduplication
    lower_subdomains = [str(s).lower() for s in mission.subdomains]
    assert len(lower_subdomains) == len(set(lower_subdomains)), f"Duplicate subdomains in mission: {mission.subdomains}"
    assert "db.internal.example.com" in lower_subdomains
    assert "api.example.com" in lower_subdomains

    # Verify KnowledgeGraph nodes and edges integrity
    graph = mission.attack_surface_graph
    sub_nodes = [n for n in graph.nodes.values() if n.type == "subdomain"]
    sub_node_values = [n.value.lower() for n in sub_nodes]
    assert len(sub_node_values) == len(set(sub_node_values)), f"Duplicate subdomain nodes in graph: {sub_node_values}"

    # Verify graph cycles: subdomain node shouldn't have self-referential edges
    for edge in graph.edges:
        assert edge.source != edge.target, f"Self loop detected on edge: {edge}"


def test_repeated_collector_executions_idempotency():
    """Verify that executing collector multiple times maintains subdomain deduplication and graph consistency."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://app.example.com"]

    def mock_get(mission_arg, url, **kwargs):
        # Only app.example.com has the .env file
        if "app.example.com/.env" in url:
            return MockHttpResponse(
                status_code=200,
                text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nINTERNAL_HOST=api.internal.example.com",
                url=url
            )
        return MockHttpResponse(status_code=404, text="", url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])

    # Run 1
    ev1 = collector.collect(mission)
    assert len(ev1) == 1
    subdomains_count_1 = len(mission.subdomains)
    graph_node_count_1 = len(mission.attack_surface_graph.nodes)

    # Run 2 on same mission: candidates now include discovered subdomain, but only app.example.com returns 200
    ev2 = collector.collect(mission)
    assert len(ev2) == 1
    subdomains_count_2 = len(mission.subdomains)
    graph_node_count_2 = len(mission.attack_surface_graph.nodes)

    # Subdomains and graph nodes should NOT duplicate
    assert subdomains_count_2 == subdomains_count_1
    assert graph_node_count_2 == graph_node_count_1


def test_recursive_multi_hop_subdomain_expansion_convergence():
    """Verify that multi-round discovery loops terminate cleanly when no new subdomains are found."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://seed.example.com"]

    # Round 1: seed -> host1.example.com
    # Round 2: host1 -> host2.example.com
    # Round 3: host2 -> host1.example.com (circular reference, must converge)
    def mock_get(mission_arg, url, **kwargs):
        if "seed.example.com/.env" in url:
            return MockHttpResponse(status_code=200, text="NEXT_HOST=host1.example.com", url=url)
        elif "host1.example.com/.env" in url:
            return MockHttpResponse(status_code=200, text="NEXT_HOST=host2.example.com", url=url)
        elif "host2.example.com/.env" in url:
            return MockHttpResponse(status_code=200, text="NEXT_HOST=host1.example.com", url=url)
        return MockHttpResponse(status_code=404, url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])

    # Loop simulation
    for _ in range(5):
        collector.collect(mission)

    # Must contain exactly seed, host1, host2 without infinite explosion
    subdomains_set = set(mission.subdomains)
    assert subdomains_set == {"host1.example.com", "host2.example.com"}
    assert len(mission.subdomains) == 2


# ==============================================================================
# Scenario 2: Mixed Target Scopes
# ==============================================================================

def test_mixed_target_scopes_extraction():
    """Verify SecretExtractor cleanly separates in-scope target subdomains, private internal suffixes, and external third parties."""
    extractor = SecretExtractor()
    sample_text = f"""
    # In-scope subdomains
    AUTH_SERVICE=https://auth.target.corp.example.com:8080/v1
    INTERNAL_PORTAL=http://portal.example.com/login
    
    # Internal domain suffixes (non-target suffix)
    DB_MASTER=postgres://admin:secret@db01.cluster.local:5432/main
    KUBE_DNS=redis.default.svc.cluster.local
    CORP_INTRANET=http://wiki.corp/docs
    LEGACY_HOST=backup.intranet
    
    # Third-party external domains (MUST NOT be treated as internal/target subdomains)
    GITHUB_URL=https://github.com/org/repo
    SLACK_ENDPOINT=https://hooks.slack.com/services/T00000000/B00000000/{"XXXXXXXXXXXXXXXXXXXXXXXX"}
    GOOGLE_API=https://storage.googleapis.com/bucket/file
    EXTERNAL_API=https://api.stripe.com/v1/charges
    EVIL_URL=https://evil-attacker.com/leak
    """
    results = extractor.extract(sample_text, target_domain="example.com")
    internal_domains = results["internal_domains"]

    # In-scope subdomains must be included
    assert "auth.target.corp.example.com" in internal_domains
    assert "portal.example.com" in internal_domains

    # Internal suffixes must be included
    assert "db01.cluster.local" in internal_domains
    assert "redis.default.svc.cluster.local" in internal_domains
    assert "wiki.corp" in internal_domains
    assert "backup.intranet" in internal_domains

    # External third parties must NOT be present
    assert "github.com" not in internal_domains
    assert "hooks.slack.com" not in internal_domains
    assert "storage.googleapis.com" not in internal_domains
    assert "api.stripe.com" not in internal_domains
    assert "evil-attacker.com" not in internal_domains


def test_scope_resolver_blocking_handled_gracefully():
    """Verify that if AuthenticatedHttpClient scope resolver returns non-200 or blocks, collector handles gracefully."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://inscope.example.com", "https://out-of-scope-attacker.com"]

    def mock_get(mission_arg, url, **kwargs):
        if "out-of-scope" in url:
            # Simulate ScopeResolver / client blocking
            return MockHttpResponse(status_code=403, text="Scope blocked", url=url)
        elif "inscope.example.com/.env" in url:
            return MockHttpResponse(status_code=200, text="SECRET_KEY=valid_secret_12345", url=url)
        return MockHttpResponse(status_code=404, url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    assert evidence[0].metadata["host"] == "https://inscope.example.com"


# ==============================================================================
# Scenario 3: Empty / Nil / Malformed Mission States
# ==============================================================================

def test_collector_and_planner_empty_and_nil_mission_states():
    """Verify collector, gap analyzer, and task generator handle empty/nil/malformed mission states gracefully without crashing."""
    collector = InformationDisclosureCollector()

    # 1. Mission with None attributes
    class NilMission:
        id = None
        target = None
        subdomains = None
        live_hosts = None
        endpoints = None
        technologies = None
        vulnerabilities = None
        evidence = None
        attack_surface_graph = None
        graph = None
        tool_runs = None
        execution_history = None
        task_states = None
        research_tasks = None

    nil_mission = NilMission()
    res = collector.collect(nil_mission)
    assert res == []

    # 2. Gap analyzer on nil mission
    analyzer = GapAnalyzer(nil_mission)
    gaps = analyzer.analyze()
    assert isinstance(gaps, list)
    assert len(gaps) > 0

    # 3. Task generator on nil mission
    task_gen = TaskGenerator(nil_mission)
    recon_tasks = task_gen.generate_recon_tasks()
    assert isinstance(recon_tasks, list)
    assert len(recon_tasks) == 5

    # 4. Task generator from_gaps on nil mission
    gap_tasks = task_gen.from_gaps(gaps)
    assert isinstance(gap_tasks, list)

    # 5. AttackSurfaceGraphBuilder on nil mission
    builder = AttackSurfaceGraphBuilder()
    graph = builder.build(nil_mission)
    assert isinstance(graph, KnowledgeGraph)


def test_collector_malformed_asset_collections():
    """Verify collector handles lists containing None, empty strings, and empty dicts."""
    mission = MockMission(target="example.com")
    mission.live_hosts = [None, "", {}, {"url": ""}, {"host": None}, "https://valid.example.com"]
    mission.endpoints = [None, "", {}, {"url": None}]
    mission.subdomains = [None, "", {}]

    mock_client = MagicMock()
    mock_client.get.return_value = MockHttpResponse(status_code=404)

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    ev = collector.collect(mission)
    assert ev == []
    # Verify mock_client was only called for valid.example.com
    assert mock_client.get.call_count == 1


# ==============================================================================
# Scenario 4: Network Failure Injection & Anomaly Resilience
# ==============================================================================

@pytest.mark.parametrize("exception_to_raise", [
    httpx.ConnectTimeout("Connection timed out after 5000ms"),
    httpx.ReadTimeout("Read timed out"),
    httpx.ConnectError("Failed to establish a new connection: [Errno 111] Connection refused"),
    httpx.RemoteProtocolError("Server disconnected unexpectedly"),
    ssl.SSLError("SSL: CERTIFICATE_VERIFY_FAILED certificate verify failed"),
    ConnectionResetError("Connection reset by peer"),
    Exception("Unknown socket error"),
])
def test_collector_network_failure_injection(exception_to_raise):
    """Verify collector handles any network or TLS exception gracefully without aborting mission execution."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://app1.example.com", "https://app2.example.com"]

    call_count = 0

    def mock_get(mission_arg, url, **kwargs):
        nonlocal call_count
        call_count += 1
        if "app1" in url:
            raise exception_to_raise
        elif "app2" in url and ".env" in url:
            return MockHttpResponse(status_code=200, text="SECRET_KEY=1234567890abcdef", url=url)
        return MockHttpResponse(status_code=404, text="", url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)

    # App1 should fail gracefully and not prevent App2 from completing
    assert len(evidence) == 1
    assert evidence[0].metadata["host"] == "https://app2.example.com"
    assert call_count >= 2


def test_collector_huge_payload_and_binary_garbage():
    """Verify SecretExtractor and collector survive large 5MB payloads and unusual byte sequences without memory leaks or regex catastrophic backtracking."""
    mission = MockMission(target="example.com")
    mission.live_hosts = ["https://huge.example.com"]

    garbage = "A" * 1000000 + "\n" + "x=123;" * 100000 + "\n"
    payload = garbage + "DATABASE_URL=postgres://dbuser:StrongPassword123!@db.internal.example.com:5432/app\n"

    mock_client = MagicMock()
    mock_client.get.return_value = MockHttpResponse(status_code=200, text=payload, url="https://huge.example.com/.env")

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    assert len(evidence[0].metadata["secrets"]) >= 1
    assert "db.internal.example.com" in evidence[0].metadata["internal_domains"]


# ==============================================================================
# Scenario 5: Attack Surface Graph Feedback Loop & DAG Expansion
# ==============================================================================

def test_attack_surface_graph_feedback_loop_end_to_end():
    """
    Test full cycle:
    1. Initial state: live host exists.
    2. Gap analyzer detects info disclosure gap.
    3. Task generator schedules info disclosure task.
    4. Info disclosure collector executes and discovers new subdomains.
    5. Knowledge graph updates with discovered subdomains and edges.
    6. Downstream Gap analyzer verifies info disclosure gap is resolved.
    7. Downstream TaskGenerator generates new recon tasks ingesting newly expanded subdomains.
    """
    mission = MockMission(target="acme.corp")
    mission.live_hosts = ["https://auth.acme.corp"]
    mission.subdomains = ["auth.acme.corp"]

    # Step 1: Initial Gap Analysis
    analyzer_1 = GapAnalyzer(mission)
    gaps_1 = analyzer_1.analyze()
    gap_areas_1 = [g.area for g in gaps_1]
    assert "Information Disclosure" in gap_areas_1

    # Step 2: Task Generator creates recon tasks
    task_gen_1 = TaskGenerator(mission)
    recon_tasks_1 = task_gen_1.generate_recon_tasks()
    info_tasks = [t for t in recon_tasks_1 if t.metadata.get("tool_id") == "info_disclosure"]
    assert len(info_tasks) == 1
    assert info_tasks[0].dependencies == ["Fingerprint Live Hosts"]

    # Step 3: Run Info Disclosure Collector
    def mock_get(mission_arg, url, **kwargs):
        if ".env" in url:
            return MockHttpResponse(
                status_code=200,
                text="VAULT_ADDR=https://vault.internal.acme.corp:8200\nAPI_GATEWAY=https://api.acme.corp",
                url=url
            )
        return MockHttpResponse(status_code=404, url=url)

    mock_client = MagicMock()
    mock_client.get.side_effect = mock_get

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)
    assert len(evidence) == 1

    # Verify mission expanded subdomains
    assert "vault.internal.acme.corp" in mission.subdomains
    assert "api.acme.corp" in mission.subdomains

    # Step 4: Rebuild / inspect attack surface graph
    graph_builder = AttackSurfaceGraphBuilder()
    graph = graph_builder.build(mission)

    assert f"subdomain:vault.internal.acme.corp" in graph.nodes
    assert f"subdomain:api.acme.corp" in graph.nodes
    assert f"live_host:https://auth.acme.corp" in graph.nodes

    # Step 5: Downstream Gap Analyzer
    analyzer_2 = GapAnalyzer(mission)
    gaps_2 = analyzer_2.analyze()
    gap_areas_2 = [g.area for g in gaps_2]

    # Information disclosure should no longer be a gap because mission.vulnerabilities has it
    assert "Information Disclosure" not in gap_areas_2

    # Step 6: Downstream Task Generator ingests new subdomains
    task_gen_2 = TaskGenerator(mission)
    recon_tasks_2 = task_gen_2.generate_recon_tasks()
    httpx_task = next(t for t in recon_tasks_2 if t.metadata.get("tool_id") == "httpx")

    # Verify that the downstream httpx task has expanded inputs including the newly discovered subdomains
    assert "vault.internal.acme.corp" in httpx_task.required_inputs
    assert "api.acme.corp" in httpx_task.required_inputs
