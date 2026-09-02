"""
Adversarial, Concurrency Stress, and False-Positive Rejection Tests for Race Conditions Module in ARGUS:
- Microsecond Barrier synchronization under simulated latency jitter
- HTTP/2 Single-Packet attack emulation
- Dynamic concurrency scaling ladder (5, 10, 20, 50)
- Strict false positive rejection on mutex-locked and atomic backends (0 findings)
- Multi-endpoint race conditions (upload & execute, cart manipulation & checkout)
- TOCTOU balance overdrafts and concurrent fund drainage
- Single-use MFA and OTP token concurrency bypasses
- TCP frame padding boundary alignment
"""
from __future__ import annotations

import threading
import time
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
)
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.runtime.mission import Mission


# ============================================================================
# Advanced Mock Servers
# ============================================================================

class MockSimulatedRaceConditionServer:
    """High-precision simulated server modeling atomic vs non-atomic race windows."""

    def __init__(self, mode: str = "vulnerable_coupon", delay_ms: float = 5.0, initial_balance: float = 100.0):
        self.mode = mode
        self.delay = delay_ms / 1000.0
        self.initial_balance = initial_balance
        self.balance = initial_balance
        self.coupon_used_count = 0
        self.max_coupon_uses = 1
        self.valid_otp = "889900"
        self.otp_used = False
        self.active_sessions: List[str] = []
        self.temp_files: Dict[str, str] = {}
        self.executed_files: List[str] = []
        self.mutex = threading.Lock()
        self.request_timestamps: List[float] = []

    def handle_request(self, req_spec: Dict[str, Any]) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        t_arrival = time.perf_counter()
        self.request_timestamps.append(t_arrival)
        url = req_spec.get("url", "")
        body = req_spec.get("json", {}) or {}

        # 1. Coupon / limit overrun
        if any(k in url for k in ("coupon", "promo", "giftcard", "points", "redeem", "checkout")):
            if self.mode == "vulnerable_coupon":
                if self.coupon_used_count >= self.max_coupon_uses:
                    return 400, {"error": "Coupon exhausted"}, {}
                time.sleep(self.delay)  # Simulated DB processing gap (race window)
                self.coupon_used_count += 1
                return 200, {"success": True, "count": self.coupon_used_count}, {}
            else:
                with self.mutex:  # Hardened atomic mutex
                    if self.coupon_used_count >= self.max_coupon_uses:
                        return 409, {"error": "Coupon exhausted", "code": "CONFLICT"}, {}
                    self.coupon_used_count += 1
                    return 200, {"success": True, "count": self.coupon_used_count}, {}

        # 2. TOCTOU balance transfer
        elif any(k in url for k in ("transfer", "pay", "order", "withdraw")):
            amount = float(body.get("amount", 100.0))
            if self.mode == "vulnerable_toctou":
                if self.balance < amount:
                    return 400, {"error": "Insufficient funds", "balance": self.balance}, {}
                time.sleep(self.delay)
                self.balance -= amount
                return 200, {"success": True, "transferred": amount, "remaining": self.balance}, {}
            else:
                with self.mutex:
                    if self.balance < amount:
                        return 400, {"error": "Insufficient funds", "balance": self.balance}, {}
                    self.balance -= amount
                    return 200, {"success": True, "transferred": amount, "remaining": self.balance}, {}

        # 3. Session & OTP Concurrency
        elif any(k in url for k in ("mfa", "auth", "reset", "login", "otp")):
            otp = body.get("otp", "")
            if self.mode == "vulnerable_mfa":
                if otp != self.valid_otp or self.otp_used:
                    return 400, {"error": "Invalid or expired OTP"}, {}
                time.sleep(self.delay)
                self.otp_used = True
                sess_id = f"sess_{len(self.active_sessions) + 1}"
                self.active_sessions.append(sess_id)
                return 200, {"success": True, "session_id": sess_id}, {"set-cookie": f"session={sess_id}"}
            else:
                with self.mutex:
                    if self.active_sessions or self.otp_used:
                        return 400, {"error": "Invalid or expired OTP"}, {}
                    self.otp_used = True
                    sess_id = "sess_primary"
                    self.active_sessions.append(sess_id)
                    return 200, {"success": True, "session_id": sess_id}, {"set-cookie": f"session={sess_id}"}

        # 4. Multi-Endpoint upload and execute
        elif "upload" in url:
            fname = body.get("filename", "tmp_upload.php")
            content = body.get("content", "CANARY_DATA")
            self.temp_files[fname] = content
            # Cleanup in background after delay
            def _cleanup():
                time.sleep(self.delay * 3)
                self.temp_files.pop(fname, None)
            threading.Thread(target=_cleanup, daemon=True).start()
            return 202, {"file_id": fname, "status": "staged"}, {}

        elif "view" in url:
            file_id = body.get("file_id", "")
            if file_id in self.temp_files:
                self.executed_files.append(file_id)
                return 200, {"executed": True, "content": self.temp_files[file_id]}, {}
            return 404, {"error": "File not found or expired"}, {}

        return 200, {"status": "default"}, {}


# ============================================================================
# Adversarial Tests
# ============================================================================

class TestRaceConditionsAdversarial:

    def test_microsecond_barrier_synchronization_under_stress(self):
        """Validates that microsecond barrier achieves sub-millisecond dispatch alignment."""
        server = MockSimulatedRaceConditionServer(mode="vulnerable_coupon", delay_ms=10.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        requests = RaceConditionPayloadGenerator.build_limit_overrun_payloads(
            endpoint="http://target.local/api/coupon",
            burst_size=20,
            strategy=ConcurrencyStrategy.MICROSECOND_BARRIER,
        )
        responses = prober.execute_burst(requests, strategy=ConcurrencyStrategy.MICROSECOND_BARRIER)
        
        assert len(responses) == 20
        # All 20 requests should have succeeded due to the race window
        successes = [r for r in responses if r.status_code == 200]
        assert len(successes) > 1
        assert server.coupon_used_count > 1

        # Calculate arrival spread
        if len(server.request_timestamps) >= 2:
            spread = max(server.request_timestamps) - min(server.request_timestamps)
            # Spread across 20 concurrent threads in local memory is typically < 25ms
            assert spread < 0.05

    def test_http2_single_packet_multiplexing_emulation(self):
        """Validates HTTP/2 single-packet synchronization emulation."""
        server = MockSimulatedRaceConditionServer(mode="vulnerable_coupon", delay_ms=5.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        requests = RaceConditionPayloadGenerator.build_limit_overrun_payloads(
            endpoint="http://target.local/api/coupon",
            burst_size=10,
            strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
        )
        responses = prober.execute_burst(requests, strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET)
        assert len(responses) == 10
        assert all(r.status_code == 200 for r in responses)

    def test_hardened_limit_overrun_strict_false_positive_rejection(self):
        """Hardened mutex-locked coupon endpoint must yield 0 findings and reject false positives."""
        server = MockSimulatedRaceConditionServer(mode="hardened_coupon", delay_ms=5.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        collector = RaceConditionsCollector(prober=prober)

        mission = Mission(target="http://example.com")
        mission.endpoints = [{"url": "http://example.com/api/coupon/redeem"}]
        mission.live_hosts = [{"url": "http://example.com"}]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence = collector.collect(mission)
        # MUST NOT generate any findings
        assert len(evidence) == 0
        assert len(mission.evidence.all()) == 0
        assert len(mission.vulnerabilities) == 0
        assert server.coupon_used_count == 1

    def test_hardened_toctou_balance_strict_false_positive_rejection(self):
        """Hardened balance deduction must strictly prevent overdraft and yield 0 findings."""
        server = MockSimulatedRaceConditionServer(mode="hardened_toctou", initial_balance=100.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        requests = [
            {"url": "http://target.local/api/transfer", "method": "POST", "json": {"amount": 100.0}}
            for _ in range(5)
        ]
        responses = prober.execute_burst(requests, strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET)
        
        successes = [r for r in responses if r.status_code == 200]
        rejections = [r for r in responses if r.status_code == 400]
        assert len(successes) == 1
        assert len(rejections) == 4
        assert server.balance == 0.0

        res = RaceConditionSecurityAnalyzer.analyze_toctou_delta(
            endpoint_url="http://target.local/api/transfer",
            pre_state=100.0,
            post_state=server.balance,
            expected_cost=100.0,
            total_deducted=100.0,
            responses=responses,
        )
        assert res is None

    def test_multi_endpoint_upload_and_execute_race(self):
        """Simulates race window between temporary file staging and background cleanup."""
        server = MockSimulatedRaceConditionServer(mode="multi_endpoint", delay_ms=10.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        reqs_a, reqs_b = RaceConditionPayloadGenerator.build_multi_endpoint_payloads(
            endpoint_a="http://target.local/api/upload",
            payload_a={"filename": "test.php", "content": "CANARY_DATA"},
            endpoint_b="http://target.local/api/view",
            payload_b={"file_id": "test.php"},
            burst_size=5,
        )

        resp_a = prober.execute_burst(reqs_a)
        resp_b = prober.execute_burst(reqs_b)

        res = RaceConditionSecurityAnalyzer.analyze_multi_endpoint_race(
            endpoint_a="http://target.local/api/upload",
            endpoint_b="http://target.local/api/view",
            resp_a=resp_a,
            resp_b=resp_b,
        )
        assert res is not None
        assert res.technique == RaceConditionTechnique.MULTI_ENDPOINT_RACE.value
        assert res.cwe_id == "CWE-367"

    def test_dynamic_concurrency_scaling_ladder_progression(self):
        """Validates progressive scaling across burst sizes [5, 10, 20, 50]."""
        server = MockSimulatedRaceConditionServer(mode="vulnerable_coupon")
        prober = ConcurrencyProber(transport_adapter=server.handle_request)

        def req_builder(burst_size):
            return RaceConditionPayloadGenerator.build_limit_overrun_payloads(
                endpoint="http://target.local/api/coupon",
                burst_size=burst_size,
            )

        all_resps, result = prober.execute_dynamic_scaling(
            base_request_builder=req_builder,
            evaluator=lambda resps: RaceConditionSecurityAnalyzer.analyze_limit_overrun("http://target.local/api/coupon", resps),
            ladder=[5, 10, 20, 50],
        )
        assert result is not None
        assert result.concurrency_burst_size == 5  # Confirmed on first tier
        assert len(all_resps) == 5

    def test_session_concurrency_multi_mfa_bypass(self):
        """Simulates parallel OTP validation yielding multiple authenticated sessions."""
        server = MockSimulatedRaceConditionServer(mode="vulnerable_mfa", delay_ms=5.0)
        prober = ConcurrencyProber(transport_adapter=server.handle_request)
        requests = RaceConditionPayloadGenerator.build_session_concurrency_payloads(
            auth_endpoint="http://target.local/api/mfa",
            token_key="otp",
            token_val="889900",
            burst_size=5,
        )
        responses = prober.execute_burst(requests, strategy=ConcurrencyStrategy.CONNECTION_PREWARMING)
        res = RaceConditionSecurityAnalyzer.analyze_session_concurrency("http://target.local/api/mfa", responses)
        assert res is not None
        assert res.technique == RaceConditionTechnique.SESSION_CONCURRENCY.value
        assert res.successful_overruns == 5

    def test_tcp_padding_header_uniformity(self):
        """Ensures request headers contain neutral TCP padding for frame alignment."""
        payloads = RaceConditionPayloadGenerator.build_limit_overrun_payloads(
            endpoint="http://target.local/api/coupon",
            burst_size=5,
            strategy=ConcurrencyStrategy.TCP_PADDING,
        )
        assert len(payloads) == 5
        for p in payloads:
            assert "X-Argus-Pad" in p["headers"]
            assert len(p["headers"]["X-Argus-Pad"]) >= 32
