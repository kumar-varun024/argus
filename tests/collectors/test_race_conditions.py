"""
Unit and Integration Tests for Race Conditions & Concurrency Vulnerabilities Detection Module in ARGUS:
- RaceConditionPayloadGenerator
- RaceConditionSecurityAnalyzer
- ConcurrencyProber
- RaceConditionsCollector (and RaceConditionCollector alias)
- ToolRegistry registration and aliases
- PluginExecutorAdapter specialist fallback
- TaskGenerator DAG recon templates and gap resolution
- AttackSurfaceGraph node and edge expansion
- CVSS & CWE-362/367 classification and scoring
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.race_conditions import (
    RaceConditionsCollector,
    RaceConditionCollector,
    RaceConditionPayloadGenerator,
    RaceConditionSecurityAnalyzer,
    ConcurrencyProber,
    ConcurrencyProbeResponse,
    RaceConditionResult,
    RaceConditionSeverity,
    RaceConditionTechnique,
    ConcurrencyStrategy,
    HARDENED_DEFENSE_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import ReportSeverity
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockConcurrencyTransport:
    """Mock transport adapter for simulating synchronized responses and server-side state machines."""

    def __init__(
        self,
        mode: str = "vulnerable_limit",  # vulnerable_limit, hardened_limit, vulnerable_toctou, hardened_toctou, vulnerable_session, hardened_session, throttled
        max_uses: int = 1,
        initial_balance: float = 100.0,
    ):
        self.mode = mode
        self.max_uses = max_uses
        self.used_count = 0
        self.balance = initial_balance
        self.sessions: List[str] = []
        self.recorded_requests: List[Dict[str, Any]] = []

    def adapter(self, req_spec: Dict[str, Any]) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        self.recorded_requests.append(req_spec)
        url = req_spec.get("url", "")
        body = req_spec.get("json", {}) or {}

        if self.mode == "vulnerable_limit":
            # Vulnerable race window allows all requests in burst to succeed
            self.used_count += 1
            return 200, {"success": True, "count": self.used_count, "discount": 50}, {"content-type": "application/json"}

        elif self.mode == "hardened_limit":
            # Atomic lock: exactly 1 succeeds, all others 409 Conflict
            if self.used_count >= self.max_uses:
                return 409, {"error": "Coupon exhausted", "code": "CONFLICT"}, {"content-type": "application/json"}
            self.used_count += 1
            return 200, {"success": True, "count": self.used_count}, {"content-type": "application/json"}

        elif self.mode == "vulnerable_toctou":
            amount = float(body.get("amount", 100.0))
            # Vulnerable: check passes before deduction
            self.balance -= amount
            return 200, {"success": True, "transferred": amount, "remaining": self.balance}, {"content-type": "application/json"}

        elif self.mode == "hardened_toctou":
            amount = float(body.get("amount", 100.0))
            if self.balance < amount:
                return 400, {"error": "Insufficient funds", "balance": self.balance}, {"content-type": "application/json"}
            self.balance -= amount
            return 200, {"success": True, "transferred": amount, "remaining": self.balance}, {"content-type": "application/json"}

        elif self.mode == "vulnerable_session":
            sess_id = f"sess_{len(self.sessions) + 1}"
            self.sessions.append(sess_id)
            return 200, {"success": True, "session_id": sess_id}, {"set-cookie": f"session={sess_id}; Path=/"}

        elif self.mode == "hardened_session":
            if self.sessions:
                return 400, {"error": "Invalid or expired OTP"}, {"content-type": "application/json"}
            sess_id = "sess_primary"
            self.sessions.append(sess_id)
            return 200, {"success": True, "session_id": sess_id}, {"set-cookie": f"session={sess_id}; Path=/"}

        elif self.mode == "throttled":
            return 429, {"error": "Too Many Requests", "retry_after": 5}, {"content-type": "application/json"}

        return 200, {"status": "ok"}, {}


# ============================================================================
# 1. Payload Generator Tests
# ============================================================================

class TestRaceConditionPayloadGenerator:
    def test_build_limit_overrun_payloads(self):
        payloads = RaceConditionPayloadGenerator.build_limit_overrun_payloads(
            endpoint="http://target.local/api/coupon",
            param_dict={"code": "SAVE50"},
            burst_size=10,
            strategy=ConcurrencyStrategy.MICROSECOND_BARRIER,
        )
        assert len(payloads) == 10
        for i, p in enumerate(payloads):
            assert p["url"] == "http://target.local/api/coupon"
            assert p["method"] == "POST"
            assert p["json"]["code"] == "SAVE50"
            assert p["headers"]["X-Burst-Seq"] == str(i)

    def test_build_toctou_probe_sequence(self):
        seq = RaceConditionPayloadGenerator.build_toctou_probe_sequence(
            check_endpoint="http://target.local/api/balance",
            mutate_endpoint="http://target.local/api/transfer",
            payload_dict={"recipient": "user2", "amount": 100.0},
            burst_size=5,
            strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
        )
        assert seq["check_request"]["url"] == "http://target.local/api/balance"
        assert len(seq["burst_requests"]) == 5
        assert seq["post_check_request"]["url"] == "http://target.local/api/balance"
        assert seq["burst_requests"][0]["json"]["amount"] == 100.0

    def test_build_session_concurrency_payloads(self):
        payloads = RaceConditionPayloadGenerator.build_session_concurrency_payloads(
            auth_endpoint="http://target.local/api/mfa/verify",
            token_key="otp",
            token_val="987654",
            burst_size=8,
            strategy=ConcurrencyStrategy.CONNECTION_PREWARMING,
        )
        assert len(payloads) == 8
        for p in payloads:
            assert p["json"]["otp"] == "987654"
            assert p["method"] == "POST"

    def test_build_multi_endpoint_payloads(self):
        reqs_a, reqs_b = RaceConditionPayloadGenerator.build_multi_endpoint_payloads(
            endpoint_a="http://target.local/api/upload",
            payload_a={"filename": "shell.php", "content": "CANARY_DATA"},
            endpoint_b="http://target.local/api/view",
            payload_b={"file_id": "tmp_shell.php"},
            burst_size=6,
            strategy=ConcurrencyStrategy.MICROSECOND_BARRIER,
        )
        assert len(reqs_a) == 6
        assert len(reqs_b) == 6
        assert reqs_a[0]["json"]["content"] == "CANARY_DATA"
        assert reqs_b[0]["json"]["file_id"] == "tmp_shell.php"

    def test_apply_tcp_padding(self):
        payloads = [{"url": "http://target.local/api", "headers": {"X-Test": "1"}}]
        padded = RaceConditionPayloadGenerator.apply_tcp_padding(payloads, pad_header="X-Argus-Pad")
        assert len(padded) == 1
        assert "X-Argus-Pad" in padded[0]["headers"]
        assert len(padded[0]["headers"]["X-Argus-Pad"]) == 64

    def test_get_dynamic_concurrency_ladder(self):
        ladder = RaceConditionPayloadGenerator.get_dynamic_concurrency_ladder()
        assert ladder == [5, 10, 20, 50]


# ============================================================================
# 2. Security Analyzer Tests
# ============================================================================

class TestRaceConditionSecurityAnalyzer:
    def test_analyze_limit_overrun_vulnerable(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, body='{"success": true}', endpoint_url="http://target.local/api/coupon")
            for _ in range(5)
        ]
        res = RaceConditionSecurityAnalyzer.analyze_limit_overrun(
            endpoint_url="http://target.local/api/coupon",
            responses=responses,
            expected_limit=1,
            strategy=ConcurrencyStrategy.MICROSECOND_BARRIER,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.LIMIT_OVERRUN.value
        assert res.severity in (RaceConditionSeverity.HIGH.value, RaceConditionSeverity.CRITICAL.value)
        assert res.successful_overruns == 5
        assert res.cwe_id == "CWE-362"

    def test_analyze_limit_overrun_secure(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, body='{"success": true}', endpoint_url="http://target.local/api/coupon"),
            ConcurrencyProbeResponse(status_code=409, body='{"error": "Exhausted"}', endpoint_url="http://target.local/api/coupon"),
            ConcurrencyProbeResponse(status_code=409, body='{"error": "Exhausted"}', endpoint_url="http://target.local/api/coupon"),
        ]
        res = RaceConditionSecurityAnalyzer.analyze_limit_overrun(
            endpoint_url="http://target.local/api/coupon",
            responses=responses,
            expected_limit=1,
            strategy=ConcurrencyStrategy.MICROSECOND_BARRIER,
        )
        assert res is None

    def test_analyze_toctou_delta_vulnerable(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, body='{"success": true}', endpoint_url="http://target.local/api/transfer")
            for _ in range(3)
        ]
        res = RaceConditionSecurityAnalyzer.analyze_toctou_delta(
            endpoint_url="http://target.local/api/transfer",
            pre_state=100.0,
            post_state=-200.0,
            expected_cost=100.0,
            total_deducted=300.0,
            responses=responses,
            strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.TOCTOU.value
        assert res.severity == RaceConditionSeverity.CRITICAL.value
        assert res.cwe_id == "CWE-367"
        assert res.cvss_score == 9.0

    def test_analyze_toctou_delta_secure(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, body='{"success": true}', endpoint_url="http://target.local/api/transfer"),
            ConcurrencyProbeResponse(status_code=400, body='{"error": "Insufficient funds"}', endpoint_url="http://target.local/api/transfer"),
        ]
        res = RaceConditionSecurityAnalyzer.analyze_toctou_delta(
            endpoint_url="http://target.local/api/transfer",
            pre_state=100.0,
            post_state=0.0,
            expected_cost=100.0,
            total_deducted=100.0,
            responses=responses,
            strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
        )
        assert res is None

    def test_analyze_session_concurrency_vulnerable(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, json_data={"session_id": f"sess_{i}"}, endpoint_url="http://target.local/api/mfa")
            for i in range(4)
        ]
        res = RaceConditionSecurityAnalyzer.analyze_session_concurrency(
            endpoint_url="http://target.local/api/mfa",
            responses=responses,
            strategy=ConcurrencyStrategy.CONNECTION_PREWARMING,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.SESSION_CONCURRENCY.value
        assert res.successful_overruns == 4

    def test_analyze_session_concurrency_secure(self):
        responses = [
            ConcurrencyProbeResponse(status_code=200, json_data={"session_id": "sess_1"}, endpoint_url="http://target.local/api/mfa"),
            ConcurrencyProbeResponse(status_code=400, json_data={"error": "Invalid OTP"}, endpoint_url="http://target.local/api/mfa"),
        ]
        res = RaceConditionSecurityAnalyzer.analyze_session_concurrency(
            endpoint_url="http://target.local/api/mfa",
            responses=responses,
            strategy=ConcurrencyStrategy.CONNECTION_PREWARMING,
        )
        assert res is None

    def test_analyze_multi_endpoint_race_vulnerable(self):
        resp_a = [ConcurrencyProbeResponse(status_code=202, body="staged", endpoint_url="http://target.local/upload")]
        resp_b = [ConcurrencyProbeResponse(status_code=200, body="Executed CANARY_DATA", endpoint_url="http://target.local/view")]
        res = RaceConditionSecurityAnalyzer.analyze_multi_endpoint_race(
            endpoint_a="http://target.local/upload",
            endpoint_b="http://target.local/view",
            resp_a=resp_a,
            resp_b=resp_b,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.MULTI_ENDPOINT_RACE.value
        assert res.cwe_id == "CWE-367"

    def test_analyze_differential_state_vulnerable(self):
        responses = [ConcurrencyProbeResponse(status_code=200, endpoint_url="http://target.local/api/points")]
        res = RaceConditionSecurityAnalyzer.analyze_differential_state(
            endpoint_url="http://target.local/api/points",
            pre_state=100,
            post_state=500,
            baseline_delta=100,
            observed_delta=400,
            responses=responses,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.DIFFERENTIAL_STATE_VERIFICATION.value
        assert res.state_delta == 400

    def test_is_hardened_defense(self):
        hardened_responses = [
            ConcurrencyProbeResponse(status_code=200, body="OK"),
            ConcurrencyProbeResponse(status_code=409, body="409 Conflict: idempotency conflict"),
            ConcurrencyProbeResponse(status_code=429, body="429 Too Many Requests"),
        ]
        assert RaceConditionSecurityAnalyzer.is_hardened_defense(hardened_responses, expected_max_success=1) is True

        vulnerable_responses = [
            ConcurrencyProbeResponse(status_code=200, body="OK"),
            ConcurrencyProbeResponse(status_code=200, body="OK"),
            ConcurrencyProbeResponse(status_code=200, body="OK"),
        ]
        assert RaceConditionSecurityAnalyzer.is_hardened_defense(vulnerable_responses, expected_max_success=1) is False


# ============================================================================
# 3. Concurrency Prober Tests
# ============================================================================

class TestConcurrencyProber:
    def test_prober_execute_burst_with_mock_transport(self):
        mock_transport = MockConcurrencyTransport(mode="vulnerable_limit")
        prober = ConcurrencyProber(transport_adapter=mock_transport.adapter)
        requests = RaceConditionPayloadGenerator.build_limit_overrun_payloads(
            endpoint="http://target.local/api/coupon",
            burst_size=5,
        )
        responses = prober.execute_burst(requests, strategy=ConcurrencyStrategy.MICROSECOND_BARRIER)
        assert len(responses) == 5
        assert all(r.status_code == 200 for r in responses)
        assert mock_transport.used_count == 5

    def test_prober_dynamic_scaling_halts_on_429(self):
        mock_transport = MockConcurrencyTransport(mode="throttled")
        prober = ConcurrencyProber(transport_adapter=mock_transport.adapter)
        
        def req_builder(n):
            return RaceConditionPayloadGenerator.build_limit_overrun_payloads("http://target.local/api/coupon", burst_size=n)

        all_resps, result = prober.execute_dynamic_scaling(
            base_request_builder=req_builder,
            evaluator=lambda resps: RaceConditionSecurityAnalyzer.analyze_limit_overrun("http://target.local/api/coupon", resps),
            ladder=[5, 10, 20, 50],
        )
        assert len(all_resps) == 5  # Halts immediately after first tier returns 429
        assert result is None


# ============================================================================
# 4. Collector Orchestrator & Quadruple State Publishing Tests
# ============================================================================

class TestRaceConditionsCollectorIntegration:
    def test_collector_discover_candidate_endpoints(self):
        collector = RaceConditionsCollector()
        mission = Mission(target="http://example.com")
        mission.endpoints = [
            {"url": "http://example.com/api/coupon/redeem"},
            {"url": "http://example.com/api/transfer"},
        ]
        candidates = collector._discover_candidate_endpoints(mission)
        assert "http://example.com/api/coupon/redeem" in candidates
        assert "http://example.com/api/transfer" in candidates
        assert any("/checkout" in c for c in candidates)

    def test_collector_collect_and_quadruple_state_publishing(self):
        mock_transport = MockConcurrencyTransport(mode="vulnerable_limit")
        prober = ConcurrencyProber(transport_adapter=mock_transport.adapter)
        collector = RaceConditionsCollector(prober=prober)

        mission = Mission(target="http://example.com")
        mission.endpoints = [{"url": "http://example.com/api/coupon/redeem"}]
        mission.live_hosts = [{"url": "http://example.com"}]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence_list = collector.collect(mission)
        assert len(evidence_list) >= 1
        ev = evidence_list[0]
        assert ev.category == "race_conditions"
        assert ev.severity in (RaceConditionSeverity.HIGH.value, RaceConditionSeverity.CRITICAL.value)
        assert ev.status == "CONFIRMED"
        assert "promo" in ev.tags or "race_conditions" in ev.tags

        # Quadruple State Check
        # 1. EvidenceStore
        assert len(mission.evidence.all()) >= 1
        # 2. Vulnerabilities list
        assert len(mission.vulnerabilities) >= 1
        assert mission.vulnerabilities[0]["cwe_id"] in ("CWE-362", "CWE-367")
        # 3. AttackSurfaceGraph nodes and edges
        graph = mission.attack_surface_graph
        assert graph.get("live_host:http://example.com") is not None
        assert graph.get("endpoint:http://example.com/api/coupon/redeem") is not None
        assert len(graph.nodes_by_type("vulnerability")) >= 1

    def test_collector_alias_compatibility(self):
        assert RaceConditionCollector is RaceConditionsCollector
        collector = RaceConditionCollector()
        assert hasattr(collector, "execute")
        assert hasattr(collector, "collect")


# ============================================================================
# 5. Pipeline, Registry, Task DAG, & CVSS Tests
# ============================================================================

class TestPipelineIntegration:
    def test_tool_registry_registration_and_aliases(self):
        tool = registry.get("race_conditions")
        assert tool is not None
        assert tool.id == "race_conditions"
        assert tool.priority == 95
        assert "race_conditions_detector" in tool.capabilities

        # Test aliases
        for alias in ("race_condition", "concurrency", "toctou", "limit_overrun", "single_packet_attack", "race"):
            resolved = registry.get(alias)
            assert resolved is not None
            assert resolved.id == "race_conditions"

    def test_plugin_executor_fallback(self):
        adapter = PluginExecutorAdapter()
        for plug_id in ("race_conditions", "race_condition", "toctou", "concurrency", "limit_overrun"):
            inst = adapter._instantiate_specialist_fallback(plug_id)
            assert inst is not None
            assert isinstance(inst, RaceConditionsCollector)

    def test_task_generator_dag_recon_template_and_gap_resolution(self):
        assert "race_conditions" in _RECON_TEMPLATES
        tmpl = _RECON_TEMPLATES["race_conditions"]
        assert tmpl["category"] == TaskCategory.EVIDENCE_CORRELATION
        assert tmpl["metadata"]["tool_id"] == "race_conditions"
        assert "Discover API Endpoints" in tmpl["dependencies"]

        mission = Mission(target="http://test.local")
        mission.endpoints = [{"url": "http://test.local/api/transfer"}]
        gen = TaskGenerator(mission)

        # Gap resolution by area
        gap = CoverageGap(area="race conditions", category=TaskCategory.EVIDENCE_CORRELATION, description="Audit TOCTOU and concurrency")
        resolved = gen._resolve_template_for_gap(gap)
        assert resolved["metadata"]["tool_id"] == "race_conditions"

        # Gap resolution by description
        gap_desc = CoverageGap(area="custom_area", category=TaskCategory.EVIDENCE_CORRELATION, description="Verify single-packet race conditions and balance overdraft")
        resolved_desc = gen._resolve_template_for_gap(gap_desc)
        assert resolved_desc["metadata"]["tool_id"] == "race_conditions"

        # from_gaps task generation
        tasks = gen.from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].metadata["tool_id"] == "race_conditions"
        assert tasks[0].required_inputs == ["http://test.local/api/transfer"]

    def test_attack_surface_graph_integration(self):
        store = EvidenceStore()
        ev = Evidence(
            category="race_conditions",
            value="limit_overrun:http://target.local/api/coupon",
            status="CONFIRMED",
            severity="high",
            title="Race Condition: Limit Overrun",
            metadata={
                "url": "http://target.local/api/coupon",
                "host": "http://target.local",
                "technique": "limit_overrun",
                "template_id": "race-conditions",
            },
        )
        store.add(ev)
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence(store, target="target.local")
        assert graph.get("endpoint:http://target.local/api/coupon") is not None
        assert len(graph.nodes_by_type("vulnerability")) >= 1

    def test_cvss_and_cwe_taxonomy(self):
        cwe_race = CVSSCalculator.get_cwe_for_category("race_conditions")
        assert cwe_race.id == "CWE-362"

        cwe_toctou = CVSSCalculator.get_cwe_for_category("toctou")
        assert cwe_toctou.id == "CWE-367"

        cvss_high = CVSSCalculator.get_approximate_cvss("race_conditions", severity="high")
        assert 7.0 <= cvss_high.score <= 8.9

        cvss_crit = CVSSCalculator.get_approximate_cvss("race_conditions", severity="critical")
        assert cvss_crit.score >= 9.0
