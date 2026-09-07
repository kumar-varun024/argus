"""race_conditions: Payload generation."""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.race_conditions.models import ConcurrencyStrategy


class RaceConditionPayloadGenerator:
    """
    Generates structured request templates, parameter variations, and batch configurations
    for concurrency, TOCTOU, limit overrun, session, and multi-endpoint race probing.
    """

    @staticmethod
    def build_limit_overrun_payloads(
        endpoint: str,
        param_dict: Optional[Dict[str, Any]] = None,
        burst_size: int = 10,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
    ) -> List[Dict[str, Any]]:
        """
        Builds identical concurrent requests targeting promo code redemption,
        gift card redemption, reward points, or limit-constrained actions.
        """
        base_params = param_dict or {"code": "PROMO2026", "coupon": "DISCOUNT50"}
        payloads: List[Dict[str, Any]] = []
        for i in range(burst_size):
            payloads.append({
                "url": endpoint,
                "method": "POST",
                "json": copy.deepcopy(base_params),
                "headers": {
                    "Content-Type": "application/json",
                    "X-Request-Index": str(i),
                    "X-Burst-Seq": str(i),
                },
            })
        if strategy == ConcurrencyStrategy.TCP_PADDING:
            payloads = RaceConditionPayloadGenerator.apply_tcp_padding(payloads)
        return payloads

    @staticmethod
    def build_toctou_probe_sequence(
        check_endpoint: str,
        mutate_endpoint: str,
        payload_dict: Optional[Dict[str, Any]] = None,
        burst_size: int = 5,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
    ) -> Dict[str, Any]:
        """
        Builds a TOCTOU probe sequence containing a pre-check query,
        a concurrent burst of balance mutation requests, and a post-check query.
        """
        mutation_body = payload_dict or {"recipient": "attacker_wallet", "amount": 100.0}
        mutation_requests: List[Dict[str, Any]] = []
        for i in range(burst_size):
            mutation_requests.append({
                "url": mutate_endpoint,
                "method": "POST",
                "json": copy.deepcopy(mutation_body),
                "headers": {
                    "Content-Type": "application/json",
                    "X-TOCTOU-Seq": str(i),
                },
            })
        if strategy == ConcurrencyStrategy.TCP_PADDING:
            mutation_requests = RaceConditionPayloadGenerator.apply_tcp_padding(mutation_requests)

        return {
            "check_request": {"url": check_endpoint, "method": "GET", "headers": {}},
            "burst_requests": mutation_requests,
            "post_check_request": {"url": check_endpoint, "method": "GET", "headers": {}},
        }

    @staticmethod
    def build_session_concurrency_payloads(
        auth_endpoint: str,
        token_key: str = "otp",
        token_val: str = "123456",
        burst_size: int = 10,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.CONNECTION_PREWARMING,
    ) -> List[Dict[str, Any]]:
        """
        Builds concurrent authentication or MFA verification requests submitting
        the same single-use token simultaneously to test for multiple session creation.
        """
        payloads: List[Dict[str, Any]] = []
        for i in range(burst_size):
            payloads.append({
                "url": auth_endpoint,
                "method": "POST",
                "json": {token_key: token_val},
                "headers": {
                    "Content-Type": "application/json",
                    "X-Auth-Attempt": str(i),
                },
            })
        if strategy == ConcurrencyStrategy.TCP_PADDING:
            payloads = RaceConditionPayloadGenerator.apply_tcp_padding(payloads)
        return payloads

    @staticmethod
    def build_multi_endpoint_payloads(
        endpoint_a: str,
        endpoint_b: str,
        payload_a: Optional[Dict[str, Any]] = None,
        payload_b: Optional[Dict[str, Any]] = None,
        burst_size: int = 10,
        stagger_ms: float = 0.0,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Builds paired request lists across separate interacting endpoints
        (e.g., upload + execute, transfer + withdraw, add_to_cart + checkout).
        """
        body_a = payload_a or {"filename": "test_exec.tmp", "content": "CANARY_DATA"}
        body_b = payload_b or {"file_id": "tmp_test_exec.tmp"}

        reqs_a: List[Dict[str, Any]] = []
        reqs_b: List[Dict[str, Any]] = []

        for i in range(burst_size):
            reqs_a.append({
                "url": endpoint_a,
                "method": "POST",
                "json": copy.deepcopy(body_a),
                "headers": {"Content-Type": "application/json", "X-Pair-Seq": str(i)},
            })
            reqs_b.append({
                "url": endpoint_b,
                "method": "POST" if payload_b else "GET",
                "json": copy.deepcopy(body_b) if payload_b else None,
                "params": body_b if not payload_b else None,
                "headers": {"Content-Type": "application/json", "X-Pair-Seq": str(i)},
                "stagger_ms": stagger_ms,
            })

        if strategy == ConcurrencyStrategy.TCP_PADDING:
            reqs_a = RaceConditionPayloadGenerator.apply_tcp_padding(reqs_a)
            reqs_b = RaceConditionPayloadGenerator.apply_tcp_padding(reqs_b)

        return reqs_a, reqs_b

    @staticmethod
    def apply_tcp_padding(
        payloads: List[Dict[str, Any]],
        pad_header: str = "X-Argus-Pad",
        target_len: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Ensures all request byte streams are padded to uniform lengths
        to prevent OS socket buffer segmentation skew.
        """
        padded: List[Dict[str, Any]] = []
        max_len = target_len or 256
        for p in payloads:
            p_copy = copy.deepcopy(p)
            headers = p_copy.setdefault("headers", {})
            headers[pad_header] = "P" * 64
            padded.append(p_copy)
        return padded

    @staticmethod
    def get_dynamic_concurrency_ladder() -> List[int]:
        """Returns the standard dynamic burst scaling ladder [5, 10, 20, 50]."""
        return [5, 10, 20, 50]
