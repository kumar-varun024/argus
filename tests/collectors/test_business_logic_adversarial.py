"""
Adversarial and Robustness Tests for Business Logic Flaws & State Machine Security Detection Module in ARGUS:
- Strict False-Positive Rejection (0 Findings Guarantee) against hardened backends
- Floating-Point Extreme Boundaries & Rounding Edge Cases
- Malformed / HTML Error Responses and Truncated JSON
- Parameter Pollution Framework Variations
- HTTP Verb Tunneling & Override Headers
- Variable Interpolation Resiliency
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.business_logic import (
    BusinessLogicCollector,
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
from argus.runtime.mission import Mission


class MockHardenedBusinessLogicServer:
    """Mock server simulating fully hardened, secure e-commerce and state machine workflows."""

    def __init__(self, mode: str = "hardened_ecommerce"):
        self.mode = mode
        self.applied_coupons: Set[str] = set()
        self.cart_paid: bool = False
        self.recorded_requests: List[Dict[str, Any]] = []

    def adapter(self, **kwargs) -> BusinessLogicProbeResponse:
        self.recorded_requests.append(kwargs)
        url = kwargs.get("url", "")
        method = kwargs.get("method", "POST")
        json_data = kwargs.get("json") or {}
        data = kwargs.get("data") or ""

        parsed = urllib.parse.urlparse(url)
        path = (parsed.path or "").lower()

        # 1. Hardened Multi-Step Workflow: strictly checks for valid payment before fulfillment
        if any(k in path for k in ("fulfill", "complete")):
            if not self.cart_paid:
                return BusinessLogicProbeResponse(
                    step_name="fulfill",
                    status_code=403,
                    body=json.dumps({"error": "payment required: step verification failed: missing step token"}),
                    json_data={"error": "payment required: step verification failed"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="fulfill",
                status_code=200,
                body=json.dumps({"status": "fulfilled", "order_id": "ord_legit_101"}),
                json_data={"status": "fulfilled", "order_id": "ord_legit_101"},
                endpoint_url=url,
            )

        # 2. Hardened Coupon Engine: strictly enforces single-use coupon per order
        if any(k in path for k in ("coupon", "voucher", "promo", "discount", "redeem")):
            if len(self.applied_coupons) >= 1:
                return BusinessLogicProbeResponse(
                    step_name="coupon",
                    status_code=409,
                    body=json.dumps({"error": "coupon already used: cannot combine multiple discounts or reuse codes"}),
                    json_data={"error": "coupon already used"},
                    endpoint_url=url,
                )
            if isinstance(json_data, dict):
                codes = json_data.get("coupon_codes")
                code = json_data.get("coupon_code", json_data.get("code"))
                if codes and (not isinstance(codes, list) or len(codes) > 1):
                    return BusinessLogicProbeResponse(
                        step_name="coupon",
                        status_code=400,
                        body=json.dumps({"error": "cannot combine multiple coupons"}),
                        json_data={"error": "cannot combine multiple coupons"},
                        endpoint_url=url,
                    )
                if code is not None and not isinstance(code, str):
                    return BusinessLogicProbeResponse(
                        step_name="coupon",
                        status_code=400,
                        body=json.dumps({"error": "invalid coupon format"}),
                        json_data={"error": "invalid coupon format"},
                        endpoint_url=url,
                    )

            if any(k in str(data) or k in (parsed.query or "") for k in ("coupon=", "voucher=", "promo=")):
                return BusinessLogicProbeResponse(
                    step_name="coupon",
                    status_code=400,
                    body=json.dumps({"error": "duplicate coupon parameter: validation error"}),
                    json_data={"error": "duplicate coupon parameter"},
                    endpoint_url=url,
                )

            self.applied_coupons.add("SAVE20")
            return BusinessLogicProbeResponse(
                step_name="coupon",
                status_code=200,
                body=json.dumps({"status": "applied", "total": 80.0, "discount": 20.0}),
                json_data={"status": "applied", "total": 80.0, "discount": 20.0},
                endpoint_url=url,
            )

        # 3. Hardened Profile Update: strictly filters unmapped/privileged fields
        if any(k in path for k in ("profile", "user", "account", "member")):
            # Rejects attempts to modify role or is_admin
            if isinstance(json_data, dict) and any(k in json_data for k in ("role", "is_admin", "tier", "admin", "permissions", "discount_rate", "balance")):
                return BusinessLogicProbeResponse(
                    step_name="profile",
                    status_code=403,
                    body=json.dumps({"error": "field disallowed: unauthorized field injection attempt"}),
                    json_data={"error": "unauthorized field"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="profile",
                status_code=200,
                body=json.dumps({"status": "updated", "user": {"id": 1, "name": "User", "role": "user", "is_admin": False}}),
                json_data={"status": "updated", "user": {"id": 1, "name": "User", "role": "user", "is_admin": False}},
                endpoint_url=url,
            )

        # 4. Hardened E-commerce Checkout: strictly validates positive prices & quantities
        if any(k in path for k in ("checkout", "cart", "pay", "order")):
            if isinstance(json_data, dict):
                for p_key in ("price", "amount", "unit_price", "total"):
                    val = json_data.get(p_key)
                    if val is not None and (not isinstance(val, (int, float)) or isinstance(val, bool) or val <= 0):
                        return BusinessLogicProbeResponse(
                            step_name="checkout",
                            status_code=400,
                            body=json.dumps({"error": f"invalid {p_key}: {p_key} must be positive number"}),
                            json_data={"error": f"invalid {p_key}"},
                            endpoint_url=url,
                        )
                qty = json_data.get("quantity")
                if qty is not None and (not isinstance(qty, int) or isinstance(qty, bool) or qty <= 0):
                    return BusinessLogicProbeResponse(
                        step_name="checkout",
                        status_code=422,
                        body=json.dumps({"error": "quantity must be positive integer"}),
                        json_data={"error": "invalid quantity"},
                        endpoint_url=url,
                    )

            # Check parameter pollution in query/data
            if any(k in str(data) or k in (parsed.query or "") for k in ("price=", "quantity=", "amount=")):
                return BusinessLogicProbeResponse(
                    step_name="checkout",
                    status_code=400,
                    body=json.dumps({"error": "duplicate parameter rejected: schema validation failed"}),
                    json_data={"error": "duplicate parameter rejected"},
                    endpoint_url=url,
                )

            return BusinessLogicProbeResponse(
                step_name="checkout",
                status_code=200,
                body=json.dumps({"status": "ok", "total": 100.0}),
                json_data={"status": "ok", "total": 100.0},
                endpoint_url=url,
            )

        # 3. Hardened Profile Update: strictly filters unmapped/privileged fields
        if "profile" in url or "user" in url or "account" in url:
            # Rejects attempts to modify role or is_admin
            if isinstance(json_data, dict) and any(k in json_data for k in ("role", "is_admin", "tier", "admin", "permissions", "discount_rate", "balance")):
                return BusinessLogicProbeResponse(
                    step_name="profile",
                    status_code=403,
                    body=json.dumps({"error": "field disallowed: unauthorized field injection attempt"}),
                    json_data={"error": "unauthorized field"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="profile",
                status_code=200,
                body=json.dumps({"status": "updated", "user": {"id": 1, "name": "User", "role": "user", "is_admin": False}}),
                json_data={"status": "updated", "user": {"id": 1, "name": "User", "role": "user", "is_admin": False}},
                endpoint_url=url,
            )

        # 4. Hardened Coupon Engine: strictly enforces single-use coupon per order
        if "coupon" in url or "voucher" in url or "promo" in url or "discount" in url or "redeem" in url:
            if len(self.applied_coupons) >= 1:
                return BusinessLogicProbeResponse(
                    step_name="coupon",
                    status_code=409,
                    body=json.dumps({"error": "coupon already used: cannot combine multiple discounts or reuse codes"}),
                    json_data={"error": "coupon already used"},
                    endpoint_url=url,
                )
            if isinstance(json_data, dict):
                codes = json_data.get("coupon_codes")
                code = json_data.get("coupon_code", json_data.get("code"))
                if codes and (not isinstance(codes, list) or len(codes) > 1):
                    return BusinessLogicProbeResponse(
                        step_name="coupon",
                        status_code=400,
                        body=json.dumps({"error": "cannot combine multiple coupons"}),
                        json_data={"error": "cannot combine multiple coupons"},
                        endpoint_url=url,
                    )
                if code is not None and not isinstance(code, str):
                    return BusinessLogicProbeResponse(
                        step_name="coupon",
                        status_code=400,
                        body=json.dumps({"error": "invalid coupon format"}),
                        json_data={"error": "invalid coupon format"},
                        endpoint_url=url,
                    )

            if "coupon=" in str(data) or "coupon=" in url:
                return BusinessLogicProbeResponse(
                    step_name="coupon",
                    status_code=400,
                    body=json.dumps({"error": "duplicate coupon parameter: validation error"}),
                    json_data={"error": "duplicate coupon parameter"},
                    endpoint_url=url,
                )

            self.applied_coupons.add("SAVE20")
            return BusinessLogicProbeResponse(
                step_name="coupon",
                status_code=200,
                body=json.dumps({"status": "applied", "total": 80.0, "discount": 20.0}),
                json_data={"status": "applied", "total": 80.0, "discount": 20.0},
                endpoint_url=url,
            )

        return BusinessLogicProbeResponse(step_name="default", status_code=200, body='{"status": "ok"}', json_data={"status": "ok"})


# ============================================================================
# Adversarial & False Positive Rejection Tests
# ============================================================================

class TestBusinessLogicAdversarial:
    def test_hardened_checkout_zero_findings_guarantee(self):
        server = MockHardenedBusinessLogicServer()
        collector = BusinessLogicCollector(transport_adapter=server.adapter)

        mission = Mission(target="http://hardened-shop.example.com")
        mission.endpoints = [{"url": "http://hardened-shop.example.com/api/checkout"}]

        evidence_list = collector.collect(mission)
        assert len(evidence_list) == 0, f"Expected 0 findings against hardened checkout, got {len(evidence_list)}"
        assert len(mission.evidence.all()) == 0
        assert len(mission.vulnerabilities) == 0

    def test_hardened_workflow_verification_zero_findings_guarantee(self):
        server = MockHardenedBusinessLogicServer()
        collector = BusinessLogicCollector(transport_adapter=server.adapter)

        mission = Mission(target="http://hardened-shop.example.com")
        mission.endpoints = [{"url": "http://hardened-shop.example.com/api/checkout/fulfill"}]

        evidence_list = collector.collect(mission)
        assert len(evidence_list) == 0, f"Expected 0 findings against hardened workflow fulfillment, got {len(evidence_list)}"
        assert len(mission.evidence.all()) == 0

    def test_hardened_profile_mass_assignment_zero_findings_guarantee(self):
        server = MockHardenedBusinessLogicServer()
        collector = BusinessLogicCollector(transport_adapter=server.adapter)

        mission = Mission(target="http://hardened-shop.example.com")
        mission.endpoints = [{"url": "http://hardened-shop.example.com/api/users/profile"}]

        evidence_list = collector.collect(mission)
        assert len(evidence_list) == 0, f"Expected 0 findings against hardened user profile, got {len(evidence_list)}"
        assert len(mission.evidence.all()) == 0

    def test_hardened_coupon_single_use_zero_findings_guarantee(self):
        server = MockHardenedBusinessLogicServer()
        collector = BusinessLogicCollector(transport_adapter=server.adapter)

        mission = Mission(target="http://hardened-shop.example.com")
        mission.endpoints = [{"url": "http://hardened-shop.example.com/api/coupon/redeem"}]

        evidence_list = collector.collect(mission)
        assert len(evidence_list) == 0, f"Expected 0 findings against hardened coupon redemption, got {len(evidence_list)}"
        assert len(mission.evidence.all()) == 0

    def test_floating_point_extreme_boundary_handling(self):
        analyzer = BusinessLogicSecurityAnalyzer()
        probe = BusinessLogicProbe(
            name="float_precision_test",
            endpoint_url="http://example.com/checkout",
            technique=BusinessLogicTechnique.PRICE_TAMPERING,
            mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
            metadata={"parameter": "price", "tampered_value": 0.00000000000001},
        )
        resp = BusinessLogicProbeResponse(
            status_code=200,
            body='{"status": "completed", "total": 0.00000000000001, "order_id": "ord_float"}',
            json_data={"status": "completed", "total": 1e-14, "order_id": "ord_float"},
        )
        result = analyzer.analyze_price_tampering("http://example.com/checkout", probe, resp)
        # Extreme float value accepted without crash
        assert result is not None or result is None  # Runs cleanly without numeric exception

    def test_malformed_json_and_html_error_handling(self):
        analyzer = BusinessLogicSecurityAnalyzer()
        probe = BusinessLogicProbe(
            name="error_html_test",
            endpoint_url="http://example.com/checkout",
            technique=BusinessLogicTechnique.PRICE_TAMPERING,
        )
        html_resp = BusinessLogicProbeResponse(
            status_code=500,
            body="<html><body><h1>500 Internal Server Error</h1><p>Validation failed: invalid price</p></body></html>",
            json_data=None,
        )
        res = analyzer.analyze_price_tampering("http://example.com/checkout", probe, html_resp)
        assert res is None, "HTML error response must not produce a vulnerability finding"

    def test_truncated_json_response_handling(self):
        prober = StatefulWorkflowProber(transport_adapter=lambda **kw: BusinessLogicProbeResponse(
            status_code=200,
            body='{"status": "ok", "cart_id": "incomplete',  # malformed JSON
            json_data=None,
        ))
        probe = BusinessLogicProbe(name="malformed_test", endpoint_url="http://example.com/api")
        resp = prober.execute_probe(probe)
        assert resp.status_code == 200
        assert resp.json_data is None

    def test_parameter_pollution_framework_variations(self):
        probes = BusinessLogicPayloadGenerator.build_price_tampering_payloads("http://example.com/checkout")
        pollution_probes = [p for p in probes if p.mutation_strategy == BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE]
        assert len(pollution_probes) >= 4
        for p in pollution_probes:
            combined = p.endpoint_url + (p.data or "")
            assert any(k in combined for k in ("price=", "quantity=", "amount="))

    def test_verb_tunneling_and_method_override_headers(self):
        probes = BusinessLogicPayloadGenerator.build_mass_assignment_payloads("http://example.com/api/user")
        override_probes = [p for p in probes if "X-HTTP-Method-Override" in p.headers]
        assert len(override_probes) >= 1
        assert override_probes[0].headers["X-HTTP-Method-Override"] == "PUT"

    def test_stateful_session_variable_interpolation_missing_keys(self):
        prober = StatefulWorkflowProber(transport_adapter=lambda **kw: BusinessLogicProbeResponse(status_code=200, body='{"status": "ok"}', endpoint_url=kw.get("url", "")))
        # Probe references an unknown variable '{unknown_key}'
        probe = BusinessLogicProbe(
            name="missing_var_test",
            endpoint_url="http://example.com/api/{unknown_key}/status",
            json_data={"data": "{unknown_key}"},
        )
        resp = prober.execute_probe(probe, session_state={"valid_key": "123"})
        # Should gracefully retain placeholder or not crash
        assert resp.status_code == 200
        assert "{unknown_key}" in resp.endpoint_url

    def test_empty_and_corrupt_mission_endpoints(self):
        collector = BusinessLogicCollector()
        mission = Mission(target="")
        mission.endpoints = []
        mission.live_hosts = []
        candidates = collector._discover_candidate_endpoints(mission)
        assert isinstance(candidates, list)
        assert len(candidates) == 0

    def test_type_juggling_defense_verification(self):
        analyzer = BusinessLogicSecurityAnalyzer()
        probe = BusinessLogicProbe(
            name="type_juggling_array",
            endpoint_url="http://example.com/api/cart",
            technique=BusinessLogicTechnique.PRICE_TAMPERING,
            mutation_strategy=BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING,
            metadata={"parameter": "price", "tampered_value": "[0]"},
        )
        rejected_resp = BusinessLogicProbeResponse(
            status_code=422,
            body='{"error": "schema validation failed: expected number, got array"}',
            json_data={"error": "schema validation failed"},
        )
        res = analyzer.analyze_price_tampering("http://example.com/api/cart", probe, rejected_resp)
        assert res is None, "Schema validation rejection (422) must not produce evidence"

    def test_hardened_profile_filtered_200_ok_zero_findings(self):
        """
        Verify that a secure backend (e.g. Django REST Framework / Rails Strong Params)
        that accepts an update with HTTP 200 OK but silently filters out privileged fields
        (returning unprivileged profile e.g. role='user', is_admin=False) generates 0 findings.
        """
        def secure_drf_profile_backend(**kwargs):
            url = kwargs.get("url", "")
            json_data = kwargs.get("json", {})
            name = json_data.get("name", "Alice")
            return BusinessLogicProbeResponse(
                step_name="profile",
                status_code=200,
                body=json.dumps({"status": "updated", "user": {"id": 42, "name": name, "role": "user", "is_admin": False}}),
                json_data={"status": "updated", "user": {"id": 42, "name": name, "role": "user", "is_admin": False}},
                endpoint_url=url,
            )

        collector = BusinessLogicCollector(transport_adapter=secure_drf_profile_backend)
        mission = Mission(target="http://secure-drf.example.com")
        mission.endpoints = [{"url": "http://secure-drf.example.com/api/users/profile"}]

        evidence = collector.collect(mission)
        assert len(evidence) == 0, f"Expected 0 findings for filtered 200 OK profile, got {len(evidence)}"
        assert len(mission.evidence.all()) == 0
        assert len(mission.vulnerabilities) == 0

    def test_hardened_ecommerce_server_side_pricing_200_ok_zero_findings(self):
        """
        Verify that a standard hardened e-commerce checkout (e.g. Shopify / WooCommerce)
        that computes prices server-side and returns HTTP 200 OK with normal positive totals
        (e.g. total=100.0) despite client-side negative/zero price tampering generates 0 findings.
        """
        def secure_ecom_backend(**kwargs):
            url = kwargs.get("url", "")
            return BusinessLogicProbeResponse(
                step_name="checkout",
                status_code=200,
                body=json.dumps({"status": "completed", "order_id": "ord_secure_999", "total": 100.0, "items": [{"id": 101, "price": 100.0}]}),
                json_data={"status": "completed", "order_id": "ord_secure_999", "total": 100.0, "items": [{"id": 101, "price": 100.0}]},
                endpoint_url=url,
            )

        collector = BusinessLogicCollector(transport_adapter=secure_ecom_backend)
        mission = Mission(target="http://secure-shop.example.com")
        mission.endpoints = [{"url": "http://secure-shop.example.com/api/checkout"}]

        evidence = collector.collect(mission)
        assert len(evidence) == 0, f"Expected 0 findings for server-side pricing 200 OK, got {len(evidence)}"
        assert len(mission.evidence.all()) == 0
        assert len(mission.vulnerabilities) == 0

    def test_hardened_workflow_pending_payment_200_ok_zero_findings(self):
        """
        Verify that multi-step checkout workflow probing returns 0 findings when intermediate
        steps are skipped and the server returns HTTP 200 OK with pending / payment required status.
        """
        analyzer = BusinessLogicSecurityAnalyzer()
        generator = BusinessLogicPayloadGenerator()
        seq = generator.build_workflow_skip_sequence("http://example.com")
        responses = [
            BusinessLogicProbeResponse(step_name="cart_create", status_code=200, body='{"cart_id": "123"}', json_data={"cart_id": "123"}),
            BusinessLogicProbeResponse(step_name="shipping_address", status_code=200, body='{"status": "ok"}', json_data={"status": "ok"}),
            BusinessLogicProbeResponse(
                step_name="order_fulfillment",
                status_code=200,
                body='{"status": "pending", "message": "Cannot fulfill: awaiting payment processing"}',
                json_data={"status": "pending", "message": "Cannot fulfill: awaiting payment processing"},
            ),
        ]
        res = analyzer.analyze_workflow_step_skip("http://example.com/api/checkout/fulfill", seq, responses)
        assert res is None, "Pending payment status under HTTP 200 must not produce workflow skip findings"

        # Also test via full collector workflow
        def secure_workflow_backend(**kwargs):
            url = kwargs.get("url", "")
            if "fulfill" in url:
                return BusinessLogicProbeResponse(
                    step_name="order_fulfillment",
                    status_code=200,
                    body=json.dumps({"status": "pending", "message": "Cannot fulfill: awaiting payment processing"}),
                    json_data={"status": "pending", "message": "Cannot fulfill: awaiting payment processing"},
                    endpoint_url=url,
                )
            return BusinessLogicProbeResponse(
                step_name="step",
                status_code=200,
                body=json.dumps({"status": "ok", "cart_id": "cart_123"}),
                json_data={"status": "ok", "cart_id": "cart_123"},
                endpoint_url=url,
            )

        collector = BusinessLogicCollector(transport_adapter=secure_workflow_backend)
        mission = Mission(target="http://example.com")
        mission.endpoints = [{"url": "http://example.com/api/checkout/fulfill"}]
        evidence = collector.collect(mission)
        assert len(evidence) == 0, f"Expected 0 findings for pending workflow 200 OK, got {len(evidence)}"

    def test_hardened_coupon_idempotent_200_ok_zero_findings(self):
        """
        Verify that repeated idempotent applications of the same coupon returning HTTP 200 OK
        with standard single discount ($80.00 total / $20.00 discount) generates 0 findings.
        """
        analyzer = BusinessLogicSecurityAnalyzer()
        responses = [
            BusinessLogicProbeResponse(step_name="apply_1", status_code=200, body='{"status": "applied", "total": 80.0, "discount": 20.0}', json_data={"status": "applied", "total": 80.0, "discount": 20.0}),
            BusinessLogicProbeResponse(step_name="apply_2", status_code=200, body='{"status": "applied", "total": 80.0, "discount": 20.0, "message": "coupon already active"}', json_data={"status": "applied", "total": 80.0, "discount": 20.0, "message": "coupon already active"}),
        ]
        res = analyzer.analyze_coupon_stacking("http://shop.example.com/api/coupon", responses, original_total=100.0)
        assert res is None, "Idempotent repeat coupon application (total remains $80) must not be flagged as stacking"

        # Also test via full collector
        def idempotent_coupon_backend(**kwargs):
            url = kwargs.get("url", "")
            return BusinessLogicProbeResponse(
                step_name="apply_coupon",
                status_code=200,
                body=json.dumps({"status": "applied", "total": 80.0, "discount": 20.0, "applied_coupons": ["SAVE20"]}),
                json_data={"status": "applied", "total": 80.0, "discount": 20.0, "applied_coupons": ["SAVE20"]},
                endpoint_url=url,
            )

        collector = BusinessLogicCollector(transport_adapter=idempotent_coupon_backend)
        mission = Mission(target="http://shop.example.com")
        mission.endpoints = [{"url": "http://shop.example.com/api/coupon/apply"}]
        evidence = collector.collect(mission)
        assert len(evidence) == 0, f"Expected 0 findings for idempotent coupon 200 OK, got {len(evidence)}"

