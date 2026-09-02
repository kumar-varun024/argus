"""
Unit and Integration Tests for Business Logic Flaws & State Machine Security Detection Module in ARGUS:
- BusinessLogicPayloadGenerator
- BusinessLogicSecurityAnalyzer
- StatefulWorkflowProber
- BusinessLogicCollector (and BusinessLogicFlawsCollector alias)
- ToolRegistry registration and capability aliases
- PluginExecutorAdapter specialist fallback
- TaskGenerator DAG recon templates and gap resolution
- AttackSurfaceGraph node and edge expansion (Section 22)
- CVSS & CWE-840/602/915/799 classification and scoring
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.business_logic import (
    BusinessLogicCollector,
    BusinessLogicFlawsCollector,
    BusinessLogicPayloadGenerator,
    BusinessLogicSecurityAnalyzer,
    StatefulWorkflowProber,
    BusinessLogicResult,
    BusinessLogicSeverity,
    BusinessLogicTechnique,
    BusinessLogicMutationStrategy,
    WorkflowStep,
    WorkflowSequence,
    BusinessLogicProbe,
    BusinessLogicProbeResponse,
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
from argus.reporting.processor import EvidenceProcessor
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockBusinessLogicTransport:
    """Mock transport adapter simulating business logic endpoints and backend state machines."""

    def __init__(
        self,
        mode: str = "vulnerable_checkout",
        initial_balance: float = 100.0,
    ):
        self.mode = mode
        self.balance = initial_balance
        self.recorded_requests: List[Dict[str, Any]] = []
        self.applied_coupons: List[str] = []
        self.user_role = "user"
        self.is_admin = False

    def adapter(self, **kwargs) -> BusinessLogicProbeResponse:
        self.recorded_requests.append(kwargs)
        url = kwargs.get("url", "")
        method = kwargs.get("method", "POST")
        json_data = kwargs.get("json") or {}
        data = kwargs.get("data") or ""

        if self.mode == "vulnerable_checkout":
            # Accepts negative price or 0 price checkout
            price = json_data.get("price", 100.0) if isinstance(json_data, dict) else 100.0
            quantity = json_data.get("quantity", 1) if isinstance(json_data, dict) else 1
            return BusinessLogicProbeResponse(
                step_name="checkout",
                status_code=200,
                body=json.dumps({"status": "completed", "order_id": "ord_123", "total": price * quantity, "success": True}),
                json_data={"status": "completed", "order_id": "ord_123", "total": price * quantity, "success": True},
                endpoint_url=url,
            )

        elif self.mode == "hardened_checkout":
            price = json_data.get("price", 100.0) if isinstance(json_data, dict) else 100.0
            quantity = json_data.get("quantity", 1) if isinstance(json_data, dict) else 1
            if price <= 0 or quantity <= 0:
                return BusinessLogicProbeResponse(
                    step_name="checkout",
                    status_code=400,
                    body=json.dumps({"error": "invalid price: price must be positive", "code": "VALIDATION_FAILED"}),
                    json_data={"error": "invalid price: price must be positive"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="checkout",
                status_code=200,
                body=json.dumps({"status": "completed", "order_id": "ord_123", "total": 100.0}),
                json_data={"status": "completed", "order_id": "ord_123", "total": 100.0},
                endpoint_url=url,
            )

        elif self.mode == "vulnerable_workflow_skip":
            # Directly allows fulfillment without intermediate payment token
            if "fulfill" in url or "complete" in url:
                return BusinessLogicProbeResponse(
                    step_name="fulfillment",
                    status_code=200,
                    body=json.dumps({"status": "fulfilled", "order_id": "ord_skip_999", "success": True}),
                    json_data={"status": "fulfilled", "order_id": "ord_skip_999", "success": True},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="cart",
                status_code=200,
                body=json.dumps({"status": "ok", "cart_id": "cart_123", "id": "cart_123"}),
                json_data={"status": "ok", "cart_id": "cart_123", "id": "cart_123"},
                endpoint_url=url,
            )

        elif self.mode == "hardened_workflow_skip":
            if "fulfill" in url and "payment_id" not in kwargs.get("json", {}):
                return BusinessLogicProbeResponse(
                    step_name="fulfillment",
                    status_code=403,
                    body=json.dumps({"error": "payment required: step verification failed"}),
                    json_data={"error": "payment required: step verification failed"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="step",
                status_code=200,
                body=json.dumps({"status": "ok", "cart_id": "cart_123"}),
                json_data={"status": "ok", "cart_id": "cart_123"},
                endpoint_url=url,
            )

        elif self.mode == "vulnerable_mass_assignment":
            if isinstance(json_data, dict):
                if "role" in json_data:
                    self.user_role = json_data["role"]
                if "is_admin" in json_data:
                    self.is_admin = json_data["is_admin"]
            return BusinessLogicProbeResponse(
                step_name="profile_update",
                status_code=200,
                body=json.dumps({"status": "updated", "user": {"id": 42, "role": self.user_role, "is_admin": self.is_admin}}),
                json_data={"status": "updated", "user": {"id": 42, "role": self.user_role, "is_admin": self.is_admin}},
                endpoint_url=url,
            )

        elif self.mode == "hardened_mass_assignment":
            # Strips out privileged parameters
            return BusinessLogicProbeResponse(
                step_name="profile_update",
                status_code=200,
                body=json.dumps({"status": "updated", "user": {"id": 42, "role": "user", "is_admin": False}}),
                json_data={"status": "updated", "user": {"id": 42, "role": "user", "is_admin": False}},
                endpoint_url=url,
            )

        elif self.mode == "vulnerable_coupon_stacking":
            self.applied_coupons.append("SAVE20")
            discount = len(self.applied_coupons) * 20.0
            total = max(-20.0, 100.0 - discount)
            return BusinessLogicProbeResponse(
                step_name="apply_coupon",
                status_code=200,
                body=json.dumps({"status": "applied", "applied_coupons": self.applied_coupons, "total": total, "discount": discount}),
                json_data={"status": "applied", "applied_coupons": self.applied_coupons, "total": total, "discount": discount},
                endpoint_url=url,
            )

        elif self.mode == "hardened_coupon":
            if self.applied_coupons:
                return BusinessLogicProbeResponse(
                    step_name="apply_coupon",
                    status_code=400,
                    body=json.dumps({"error": "coupon already used: cannot combine multiple discounts"}),
                    json_data={"error": "coupon already used"},
                    endpoint_url=url,
                )
            self.applied_coupons.append("SAVE20")
            return BusinessLogicProbeResponse(
                step_name="apply_coupon",
                status_code=200,
                body=json.dumps({"status": "applied", "total": 80.0, "discount": 20.0}),
                json_data={"status": "applied", "total": 80.0, "discount": 20.0},
                endpoint_url=url,
            )

        return BusinessLogicProbeResponse(step_name="default", status_code=200, body='{"status": "ok"}', json_data={"status": "ok"})


# ============================================================================
# 1. Enums and Data Models Tests
# ============================================================================

class TestBusinessLogicEnumsAndModels:
    def test_enums_values_and_aliases(self):
        assert BusinessLogicSeverity.CRITICAL == "critical"
        assert BusinessLogicSeverity.HIGH == "high"
        assert BusinessLogicSeverity.MEDIUM == "medium"
        assert BusinessLogicSeverity.LOW == "low"
        assert BusinessLogicSeverity.INFO == "info"

        assert BusinessLogicTechnique.PRICE_TAMPERING == "price_tampering"
        assert BusinessLogicTechnique.WORKFLOW_STEP_SKIP == "workflow_step_skip"
        assert BusinessLogicTechnique.MASS_ASSIGNMENT == "mass_assignment"
        assert BusinessLogicTechnique.COUPON_STACKING == "coupon_stacking"
        assert BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION == "differential_state_verification"

        assert BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION == "boundary_negative_injection"
        assert BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING == "type_juggling_schema_tampering"
        assert BusinessLogicMutationStrategy.OUT_OF_SEQUENCE_DISPATCH == "out_of_sequence_dispatch"
        assert BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION == "verb_content_type_inversion"
        assert BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE == "parameter_pollution_duplicate"

    def test_result_post_init_synchronization(self):
        res = BusinessLogicResult(
            technique="price_tampering",
            mutation_strategy="boundary_negative_injection",
            severity="critical",
            confidence=0.98,
            payload={"price": -50},
            matched_signature="negative_price_accepted",
            evidence_snippet="Server accepted price=-50",
            endpoint_url="http://example.com/checkout",
        )
        assert res.strategy == "boundary_negative_injection"
        assert res.mutation_strategy == "boundary_negative_injection"
        assert res.vulnerability_type == "price_tampering"
        assert res.metadata["url"] == "http://example.com/checkout"
        assert res.cwe_id == "CWE-840"

    def test_workflow_step_and_sequence_models(self):
        step = WorkflowStep(name="cart", url="http://example.com/cart", method="POST", json_data={"qty": 1})
        seq = WorkflowSequence(name="checkout_flow", steps=[step], target_step_index=0, skip_step_indices=[])
        assert seq.name == "checkout_flow"
        assert len(seq.steps) == 1
        assert seq.steps[0].name == "cart"


# ============================================================================
# 2. Payload Generator Tests
# ============================================================================

class TestBusinessLogicPayloadGenerator:
    def test_build_price_tampering_payloads(self):
        url = "http://example.com/api/checkout"
        probes = BusinessLogicPayloadGenerator.build_price_tampering_payloads(url)
        assert len(probes) >= 10
        strategies = {p.mutation_strategy for p in probes}
        assert BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION in strategies
        assert BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING in strategies
        assert BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE in strategies

        # Check negative and zero payloads
        negative_found = any(p.json_data and p.json_data.get("price") == -50.00 for p in probes)
        zero_found = any(p.json_data and p.json_data.get("price") == 0 for p in probes)
        assert negative_found
        assert zero_found

    def test_build_mass_assignment_payloads(self):
        url = "http://example.com/api/users/profile"
        probes = BusinessLogicPayloadGenerator.build_mass_assignment_payloads(url)
        assert len(probes) >= 10
        injected_fields = [p.metadata.get("injected_field") for p in probes]
        assert "role" in injected_fields
        assert "is_admin" in injected_fields
        assert "tier" in injected_fields
        assert "permissions" in injected_fields

    def test_build_coupon_stacking_payloads(self):
        url = "http://example.com/api/coupon/apply"
        probes = BusinessLogicPayloadGenerator.build_coupon_stacking_payloads(url, coupon_codes=["SAVE20", "SAVE50"])
        assert len(probes) >= 4
        array_probe = next(p for p in probes if p.name == "coupon_array_duplicate_stacking")
        assert len(array_probe.json_data["coupon_codes"]) == 3

    def test_build_workflow_skip_sequence(self):
        seq = BusinessLogicPayloadGenerator.build_workflow_skip_sequence("http://example.com")
        assert len(seq.steps) == 4
        assert 2 in seq.skip_step_indices  # Payment step skipped
        assert seq.steps[-1].name == "order_fulfillment"

    def test_build_verb_content_type_inversions(self):
        url = "http://example.com/api/confirm"
        probes = BusinessLogicPayloadGenerator.build_verb_content_type_inversions(url, method="POST")
        verbs = {p.method for p in probes}
        assert "PUT" in verbs
        assert "PATCH" in verbs
        assert "GET" in verbs
        content_type_probe = next(p for p in probes if "urlencoded" in p.name)
        assert content_type_probe.headers["Content-Type"] == "application/x-www-form-urlencoded"


# ============================================================================
# 3. Security Analyzer Tests
# ============================================================================

class TestBusinessLogicSecurityAnalyzer:
    def test_hardened_defense_detection(self):
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(400, "Bad Request") is True
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(403, "Forbidden") is True
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(422, "Unprocessable Entity") is True
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(200, "Error: quantity must be positive") is True
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(200, "Coupon already used") is True
        assert BusinessLogicSecurityAnalyzer.is_hardened_defense(200, '{"status": "completed", "total": 0}') is False

    def test_analyze_price_tampering_vulnerable_and_hardened(self):
        probe = BusinessLogicProbe(
            name="price_tamper",
            endpoint_url="http://example.com/checkout",
            technique=BusinessLogicTechnique.PRICE_TAMPERING,
            mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
            metadata={"parameter": "price", "tampered_value": -50.0},
        )
        vuln_resp = BusinessLogicProbeResponse(
            status_code=200,
            body='{"status": "completed", "order_id": "ord_100", "total": -50.0}',
            json_data={"status": "completed", "order_id": "ord_100", "total": -50.0},
        )
        result = BusinessLogicSecurityAnalyzer.analyze_price_tampering("http://example.com/checkout", probe, vuln_resp)
        assert result is not None
        assert result.severity == BusinessLogicSeverity.CRITICAL.value
        assert result.cwe_id == "CWE-602"
        assert result.cvss_score == 9.8

        hardened_resp = BusinessLogicProbeResponse(
            status_code=400,
            body='{"error": "invalid price: negative price not allowed"}',
        )
        hardened_result = BusinessLogicSecurityAnalyzer.analyze_price_tampering("http://example.com/checkout", probe, hardened_resp)
        assert hardened_result is None

    def test_analyze_workflow_step_skip(self):
        seq = BusinessLogicPayloadGenerator.build_workflow_skip_sequence("http://example.com")
        responses = [
            BusinessLogicProbeResponse(step_name="cart_create", status_code=200, body='{"cart_id": "c_1"}', json_data={"cart_id": "c_1"}),
            BusinessLogicProbeResponse(step_name="shipping_address", status_code=200, body='{"status": "ok"}', json_data={"status": "ok"}),
            BusinessLogicProbeResponse(step_name="order_fulfillment", status_code=200, body='{"status": "fulfilled", "order_id": "ord_999"}', json_data={"status": "fulfilled", "order_id": "ord_999"}),
        ]
        result = BusinessLogicSecurityAnalyzer.analyze_workflow_step_skip("http://example.com/api/checkout/fulfill", seq, responses)
        assert result is not None
        assert result.technique == BusinessLogicTechnique.WORKFLOW_STEP_SKIP.value
        assert result.severity == BusinessLogicSeverity.CRITICAL.value
        assert result.cwe_id == "CWE-840"

    def test_analyze_mass_assignment(self):
        probe = BusinessLogicProbe(
            name="mass_assignment_role",
            endpoint_url="http://example.com/api/profile",
            technique=BusinessLogicTechnique.MASS_ASSIGNMENT,
            mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
            metadata={"injected_field": "role", "injected_value": "admin"},
        )
        resp = BusinessLogicProbeResponse(
            status_code=200,
            body='{"status": "updated", "user": {"id": 1, "role": "admin", "is_admin": true}}',
            json_data={"status": "updated", "user": {"id": 1, "role": "admin", "is_admin": True}},
        )
        result = BusinessLogicSecurityAnalyzer.analyze_mass_assignment("http://example.com/api/profile", probe, resp)
        assert result is not None
        assert result.technique == BusinessLogicTechnique.MASS_ASSIGNMENT.value
        assert result.severity == BusinessLogicSeverity.CRITICAL.value
        assert result.cwe_id == "CWE-915"

    def test_analyze_coupon_stacking(self):
        responses = [
            BusinessLogicProbeResponse(step_name="c1", status_code=200, body='{"total": 80}', json_data={"total": 80}),
            BusinessLogicProbeResponse(step_name="c2", status_code=200, body='{"total": 60}', json_data={"total": 60}),
            BusinessLogicProbeResponse(step_name="c3", status_code=200, body='{"total": -20}', json_data={"total": -20}),
        ]
        result = BusinessLogicSecurityAnalyzer.analyze_coupon_stacking("http://example.com/api/coupon", responses, original_total=100.0, final_total=-20.0)
        assert result is not None
        assert result.technique == BusinessLogicTechnique.COUPON_STACKING.value
        assert result.severity == BusinessLogicSeverity.CRITICAL.value
        assert result.cwe_id == "CWE-799"

    def test_analyze_differential_state(self):
        result = BusinessLogicSecurityAnalyzer.analyze_differential_state(
            endpoint_url="http://example.com/api/balance",
            technique=BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION.value,
            strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION.value,
            pre_state={"balance": 100},
            post_state={"balance": 250},
            expected_post_state={"balance": 0},
        )
        assert result is not None
        assert result.cwe_id == "CWE-840"
        assert result.state_delta["post_state"] == {"balance": 250}


# ============================================================================
# 4. Stateful Workflow Prober Tests
# ============================================================================

class TestStatefulWorkflowProber:
    def test_execute_probe_with_interpolation(self):
        mock = MockBusinessLogicTransport(mode="vulnerable_checkout")
        prober = StatefulWorkflowProber(transport_adapter=mock.adapter)
        prober.session_variables["cart_id"] = "cart_abc_123"

        probe = BusinessLogicProbe(
            name="checkout_test",
            endpoint_url="http://example.com/api/cart/{cart_id}/checkout",
            json_data={"cart_id": "{cart_id}", "price": -10},
        )
        resp = prober.execute_probe(probe)
        assert resp.status_code == 200
        assert resp.endpoint_url == "http://example.com/api/cart/cart_abc_123/checkout"
        assert mock.recorded_requests[0]["json"]["cart_id"] == "cart_abc_123"

    def test_execute_workflow_step_skipping_and_extraction(self):
        mock = MockBusinessLogicTransport(mode="vulnerable_workflow_skip")
        prober = StatefulWorkflowProber(transport_adapter=mock.adapter)
        seq = BusinessLogicPayloadGenerator.build_workflow_skip_sequence("http://example.com")

        responses = prober.execute_workflow(seq)
        assert len(responses) == 3  # Step 2 was skipped (4 steps total - 1 skipped = 3)
        assert "cart_id" in prober.session_variables
        assert prober.session_variables["cart_id"] == "cart_123"


# ============================================================================
# 5. Collector Orchestration & Quadruple State Publishing Tests
# ============================================================================

class TestBusinessLogicCollector:
    def test_candidate_endpoint_discovery(self):
        mission = Mission(target="example.com")
        mission.endpoints = [
            {"url": "http://example.com/api/v1/checkout"},
            {"url": "http://example.com/api/users/profile"},
            {"url": "http://example.com/static/style.css"},  # non-candidate
        ]
        collector = BusinessLogicCollector()
        candidates = collector._discover_candidate_endpoints(mission)
        assert "http://example.com/api/v1/checkout" in candidates
        assert "http://example.com/api/users/profile" in candidates
        assert "http://example.com/static/style.css" not in candidates

    def test_collector_collect_and_quadruple_state_publishing(self):
        mock = MockBusinessLogicTransport(mode="vulnerable_checkout")
        collector = BusinessLogicCollector(transport_adapter=mock.adapter)

        mission = Mission(target="http://example.com")
        mission.endpoints = [{"url": "http://example.com/checkout"}]

        evidence_list = collector.collect(mission)
        assert len(evidence_list) >= 1
        ev = evidence_list[0]
        assert ev.category == "business_logic"
        assert ev.status == "CONFIRMED"
        assert ev.severity == "critical"

        # 1. raw_mission.evidence
        assert len(mission.evidence.all()) >= 1

        # 2. raw_mission.vulnerabilities
        assert len(mission.vulnerabilities) >= 1
        vuln_dict = mission.vulnerabilities[0]
        assert vuln_dict["cwe_id"] in ("CWE-840", "CWE-602", "CWE-915", "CWE-799")

        # 3. raw_mission.attack_surface_graph
        graph = mission.attack_surface_graph
        vuln_nodes = graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) >= 1
        ep_nodes = graph.nodes_by_type("endpoint")
        assert len(ep_nodes) >= 1
        lh_nodes = graph.nodes_by_type("live_host")
        assert len(lh_nodes) >= 1

        # Check HAS_ENDPOINT and HAS_VULNERABILITY edges
        edge_types = {e.type for e in graph.edges}
        assert "HAS_ENDPOINT" in edge_types
        assert "HAS_VULNERABILITY" in edge_types

    def test_controlled_mission_publish_finding(self):
        mock = MockBusinessLogicTransport(mode="vulnerable_mass_assignment")
        collector = BusinessLogicCollector(transport_adapter=mock.adapter)

        raw_mission = Mission(target="http://example.com")
        raw_mission.endpoints = [{"url": "http://example.com/api/users/profile"}]
        controlled = ControlledMission(raw_mission)

        evidence_list = collector.collect(controlled)
        assert len(evidence_list) >= 1
        assert len(raw_mission.evidence.all()) >= 1
        assert hasattr(raw_mission, "plugin_findings")
        assert len(raw_mission.plugin_findings) >= 1

    def test_collector_aliases(self):
        assert BusinessLogicFlawsCollector is BusinessLogicCollector
        collector = BusinessLogicCollector()
        assert collector.execute == collector.collect


# ============================================================================
# 6. Pipeline, Registry, Task DAG & Reporting Integration Tests
# ============================================================================

class TestPipelineIntegration:
    def test_registry_lookup_and_aliases(self):
        tool = registry.get("business_logic")
        assert tool is not None
        assert tool.id == "business_logic"

        aliases = [
            "business_logic_collector",
            "business_logic_detector",
            "business_logic_flaws",
            "business_logic_security",
            "state_machine",
            "state_machine_security",
            "workflow_bypass",
            "workflow_skip",
            "parameter_tampering",
            "price_tampering",
            "quantity_tampering",
            "mass_assignment",
            "coupon_stacking",
            "idempotency_abuse",
        ]
        for alias in aliases:
            resolved = registry.get(alias)
            assert resolved is not None, f"Failed to resolve alias '{alias}'"
            assert resolved.id == "business_logic"

    def test_plugin_executor_adapter_fallback(self):
        adapter = PluginExecutorAdapter()
        inst = adapter._instantiate_specialist_fallback("business_logic")
        assert isinstance(inst, BusinessLogicCollector)

        inst_collector = adapter._instantiate_specialist_fallback("business_logic_collector")
        assert isinstance(inst_collector, BusinessLogicCollector)

        inst_pt = adapter._instantiate_specialist_fallback("price_tampering")
        assert isinstance(inst_pt, BusinessLogicCollector)

    def test_task_generator_recon_template_and_gap_resolution(self):
        assert "business_logic" in _RECON_TEMPLATES
        template = _RECON_TEMPLATES["business_logic"]
        assert template["category"] == TaskCategory.EVIDENCE_CORRELATION
        assert "Discover API Endpoints" in template["dependencies"]
        assert template["metadata"]["tool_id"] == "business_logic"

        mission = Mission(target="example.com")
        mission.endpoints = [{"url": "http://example.com/checkout"}]
        tg = TaskGenerator(mission=mission)

        gap = CoverageGap(
            category=TaskCategory.EVIDENCE_CORRELATION,
            area="business logic flaws",
            description="price tampering and mass assignment flaws",
            severity=0.85,
        )
        tasks = tg.from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].title == "Validate Business Logic & State Machine Security"
        assert tasks[0].metadata.get("tool_id") == "business_logic"

    def test_attack_surface_graph_section_22(self):
        ev = Evidence(
            category="business_logic",
            value="price_tampering:http://example.com/checkout",
            source="business_logic",
            title="Business Logic Price & Quantity Tampering: http://example.com/checkout",
            metadata={
                "url": "http://example.com/checkout",
                "host": "http://example.com",
                "technique": "price_tampering",
                "template_id": "business-logic",
                "parameter": "price",
                "status_code": 200,
            },
        )
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence([ev])

        assert "endpoint:http://example.com/checkout" in graph.nodes
        assert "live_host:http://example.com" in graph.nodes
        assert "vulnerability:business-logic:http://example.com/checkout:price" in graph.nodes

        edge_types = {e.type for e in graph.edges}
        assert "HAS_ENDPOINT" in edge_types
        assert "HAS_VULNERABILITY" in edge_types

    def test_cvss_and_cwe_database_mappings(self):
        cwe_bl = CVSSCalculator.get_cwe_for_category("business_logic")
        assert cwe_bl.id == "CWE-840"

        cwe_pt = CVSSCalculator.get_cwe_for_category("price_tampering")
        assert cwe_pt.id == "CWE-602"

        cwe_ma = CVSSCalculator.get_cwe_for_category("mass_assignment")
        assert cwe_ma.id == "CWE-915"

        cwe_cs = CVSSCalculator.get_cwe_for_category("coupon_stacking")
        assert cwe_cs.id == "CWE-799"

        crit_cvss = CVSSCalculator.get_approximate_cvss("business_logic", severity="critical")
        assert crit_cvss.score >= 9.0

        high_cvss = CVSSCalculator.get_approximate_cvss("price_tampering", severity="high")
        assert 7.0 <= high_cvss.score <= 8.9

    def test_evidence_processor_impact_and_remediation(self):
        ev = Evidence(
            category="business_logic",
            value="price_tampering:http://example.com/checkout",
            source="business_logic",
            title="Business Logic Price & Quantity Tampering",
            severity="high",
            metadata={"url": "http://example.com/checkout"},
        )
        processor = EvidenceProcessor()
        finding = processor._normalize_evidence_to_finding(ev, "http://example.com")
        assert "workflow" in finding.impact.lower() or "pricing" in finding.impact.lower()
        assert "state machine" in finding.remediation.lower() or "price calculation" in finding.remediation.lower()
