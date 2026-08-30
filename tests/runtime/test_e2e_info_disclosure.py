"""
End-to-End integration tests for Information Disclosure Engine.
Validates HTTP probing, secret extraction, Evidence generation,
KnowledgeGraph expansion, and the attack surface feedback loop.
"""
import pytest

from argus.collectors.information_disclosure import InformationDisclosureCollector
from argus.runtime.mission import Mission
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.task_generator import TaskGenerator
from argus.runtime.plugins import PluginExecutorAdapter
from argus.http.client import HttpResponse


class MockE2EHttpClient:
    """Simulates real-world HTTP responses for exposed files."""

    def __init__(self):
        self.responses = {
            "https://target.corp/.env": (
                200,
                f"""
                # Production Environment Config
                APP_NAME=ArgusTarget
                DB_HOST=db.internal.target.corp
                DB_PASSWORD=SuperSecretPass_2026!
                DATABASE_URL=postgres://app_user:DbSecPass@db.internal.target.corp:5432/main_db
                AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
                AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                STRIPE_SECRET_KEY=sk_live_{"51ABC1234567890abcdefghijklm"}
                GOOGLE_API_KEY=AIzaSyD-1234567890abcdefghijklmnopqrstu
                GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
                AUTH_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
                INTERNAL_AUTH=auth.infra.internal
                INTERNAL_IP=10.240.0.5
                """,
            ),
            "https://target.corp/.git/config": (
                200,
                """
                [core]
                    repositoryformatversion = 0
                    filemode = true
                    bare = false
                [remote "origin"]
                    url = https://git.internal.target.corp/security/core-app.git
                    fetch = +refs/heads/*:refs/remotes/origin/*
                """,
            ),
        }

    def get(self, mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        if target_url in self.responses:
            code, body = self.responses[target_url]
            return HttpResponse(
                success=True,
                status_code=code,
                raw_body=body,
                body=body,
                url=target_url,
            )
        return HttpResponse(success=False, status_code=404, error="Not Found", url=target_url)


def test_e2e_information_disclosure_flow_with_graph_loop():
    """
    E2E integration test:
    1. Initialize Mission with target "target.corp" and live host "https://target.corp".
    2. Run InformationDisclosureCollector with MockE2EHttpClient.
    3. Assert Evidence creation for information_disclosure and newly discovered subdomains.
    4. Assert KnowledgeGraph node creation (live_host, endpoint, vulnerability, secret, subdomain)
       and edge wiring (HAS_ENDPOINT, HAS_VULNERABILITY, EXPOSES_SECRET, DISCLOSED_SUBDOMAIN, RESOLVES_TO).
    5. Assert attack surface graph builder faithfully reproduces graph from EvidenceStore.
    6. Assert GapAnalyzer detects newly discovered subdomains in subsequent recon loops.
    """
    mission = Mission(target="target.corp")
    mission.live_hosts = [{"url": "https://target.corp", "host": "target.corp"}]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockE2EHttpClient()
    collector = InformationDisclosureCollector(http_client=mock_client)

    # 1. Execute Collector
    evidence_list = collector.collect(mission)

    # 2. Validate Evidence Emission
    assert len(evidence_list) == 2, f"Expected 2 disclosed files, got {len(evidence_list)}"

    env_ev = next(e for e in evidence_list if e.metadata["path"] == ".env")
    assert env_ev.category == "information_disclosure"
    assert env_ev.severity == "high"
    assert env_ev.status == "CONFIRMED"
    assert env_ev.confidence == 0.95
    assert env_ev.metadata["status_code"] == 200
    assert len(env_ev.metadata["secrets"]) >= 5
    assert "db.internal.target.corp" in env_ev.metadata["internal_domains"]
    assert "auth.infra.internal" in env_ev.metadata["internal_domains"]
    assert "10.240.0.5" in env_ev.metadata["private_ips"]

    git_ev = next(e for e in evidence_list if e.metadata["path"] == ".git/config")
    assert git_ev.category == "information_disclosure"
    assert "git.internal.target.corp" in git_ev.metadata["internal_domains"]

    # 3. Validate Mission State Feedback Loop
    assert len(mission.vulnerabilities) == 2
    assert "db.internal.target.corp" in mission.subdomains
    assert "auth.infra.internal" in mission.subdomains
    assert "git.internal.target.corp" in mission.subdomains

    sub_evidence = [e for e in mission.evidence.all() if e.category == "subdomain"]
    discovered_sub_names = {e.value for e in sub_evidence}
    assert "db.internal.target.corp" in discovered_sub_names
    assert "auth.infra.internal" in discovered_sub_names
    assert "git.internal.target.corp" in discovered_sub_names

    # 4. Validate Direct KnowledgeGraph Mutation
    assert graph.get("live_host:https://target.corp") is not None
    assert graph.get("endpoint:https://target.corp/.env") is not None
    assert graph.get("endpoint:https://target.corp/.git/config") is not None
    assert graph.get("vulnerability:info-disclosure-env:https://target.corp/.env") is not None
    assert graph.get("vulnerability:info-disclosure-git-config:https://target.corp/.git/config") is not None

    # Check secret nodes
    secret_nodes = graph.nodes_by_type("secret")
    assert len(secret_nodes) >= 5

    # Check subdomain nodes
    assert graph.get("subdomain:db.internal.target.corp") is not None
    assert graph.get("subdomain:auth.infra.internal") is not None
    assert graph.get("subdomain:git.internal.target.corp") is not None

    # Check edge connections
    assert graph.are_connected("live_host:https://target.corp", "endpoint:https://target.corp/.env")
    assert graph.are_connected("endpoint:https://target.corp/.env", "vulnerability:info-disclosure-env:https://target.corp/.env")
    assert graph.are_connected("vulnerability:info-disclosure-env:https://target.corp/.env", "subdomain:db.internal.target.corp")
    assert graph.are_connected("vulnerability:info-disclosure-git-config:https://target.corp/.git/config", "subdomain:git.internal.target.corp")
    assert graph.are_connected("target:target.corp", "subdomain:db.internal.target.corp")
    assert graph.are_connected("target:target.corp", "subdomain:git.internal.target.corp")

    # 5. Validate AttackSurfaceGraphBuilder from EvidenceStore
    rebuilt_graph = AttackSurfaceGraphBuilder().build_from_evidence(
        evidence=mission.evidence,
        target="target.corp"
    )
    assert rebuilt_graph.get("endpoint:https://target.corp/.env") is not None
    assert rebuilt_graph.get("vulnerability:info-disclosure-env:https://target.corp/.env") is not None
    assert rebuilt_graph.get("subdomain:db.internal.target.corp") is not None
    assert rebuilt_graph.are_connected("vulnerability:info-disclosure-env:https://target.corp/.env", "subdomain:db.internal.target.corp")

    # 6. Validate Planner on Expanded Surface
    # TaskGenerator now sees newly discovered subdomains and feeds them into downstream recon tasks (HTTPX)
    generator = TaskGenerator(mission)
    recon_tasks = generator.generate_recon_tasks()
    httpx_task = next(t for t in recon_tasks if t.title == "Fingerprint Live Hosts")
    assert any("db.internal.target.corp" in str(inp) for inp in httpx_task.required_inputs)



def test_plugin_executor_adapter_executes_info_disclosure():
    """Verifies that PluginExecutorAdapter can dynamically execute InformationDisclosureCollector."""
    adapter = PluginExecutorAdapter()
    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    res = adapter.execute_plugin("info_disclosure", mission)
    assert res["status"] == "success"
    assert isinstance(res["plugin_instance"], InformationDisclosureCollector)
