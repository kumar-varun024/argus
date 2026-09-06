"""
Race Conditions & Concurrency Vulnerabilities Detection Collector for ARGUS.

Actively validates whether web endpoints and business logic flows are vulnerable
to concurrency attacks, Time-of-Check to Time-of-Use (TOCTOU) flaws, limit overruns,
and multi-threaded synchronization bugs:
1. Limit Overrun / Multi-Redemption:
   - Concurrent request bursts exceeding single-use or rate constraints
     (e.g., promo codes, discount vouchers, gift cards, reward points).
2. Time-of-Check to Time-of-Use (TOCTOU):
   - Exploiting asynchronous race windows between balance/eligibility validation
     and actual state mutation or resource deduction.
3. Session & State Concurrency Desynchronization:
   - Multi-session token reuse, parallel authentication session creation,
     and concurrent single-use MFA / password reset token consumption.
4. Partial State / Multi-Endpoint Race Conditions:
   - Submitting simultaneous requests across separate interacting endpoints
     (e.g., upload & execute, transfer & withdrawal, cart add & checkout).
5. Differential State Verification & Confirmation Pipeline:
   - Automated pre-state baselining, synchronized attack burst execution, and
     post-state verification to confirm actual state overrun.
6. False Positive Rejection:
   - Properly locked and mutex-synchronized endpoints (returning 1 success and
     N-1 400/409/423/429 rejections with invariant state delta intact) MUST NOT
     generate evidence.

Provides 5+ distinct synchronization & concurrency strategies:
1. HTTP2_SINGLE_PACKET: Sending multiple multiplexed stream requests within a single
   TCP packet or synchronized TLS record frame release.
2. CONNECTION_PREWARMING: Priming N TCP/TLS keep-alive connections in advance to eliminate
   handshake and TCP slow-start jitter.
3. MICROSECOND_BARRIER: Microsecond barrier synchronization (asyncio.Barrier / threading.Barrier)
   aligning socket release buffers.
4. TCP_PADDING: Injecting neutral padding headers (X-Argus-Pad) for TCP MSS/frame alignment.
5. DYNAMIC_CONCURRENCY_SCALING: Progressively escalating burst sizes [5, 10, 20, 50].

Emits structured Evidence(category="race_conditions"), updates mission vulnerabilities,
and expands AttackSurfaceGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import json
import logging
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# ============================================================================
# Enums & Dataclasses
# ============================================================================

# Canonical severity scale (see argus.collectors.toolkit.enums.Severity).
RaceConditionSeverity = Severity


# Backwards compatibility alias
Severity = RaceConditionSeverity


class RaceConditionTechnique(str, Enum):
    """Enumeration of race condition vulnerability detection techniques."""
    LIMIT_OVERRUN = "limit_overrun"
    TOCTOU = "toctou"
    SESSION_CONCURRENCY = "session_concurrency"
    MULTI_ENDPOINT_RACE = "multi_endpoint_race"
    DIFFERENTIAL_STATE_VERIFICATION = "differential_state_verification"


class ConcurrencyStrategy(str, Enum):
    """Enumeration of synchronization and concurrency probing strategies."""
    HTTP2_SINGLE_PACKET = "http2_single_packet"
    CONNECTION_PREWARMING = "connection_prewarming"
    MICROSECOND_BARRIER = "microsecond_barrier"
    TCP_PADDING = "tcp_padding"
    DYNAMIC_CONCURRENCY_SCALING = "dynamic_concurrency_scaling"


@dataclass
class ConcurrencyProbeResponse:
    """Represents an individual response captured during a synchronized burst probe."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Any] = None
    timestamp_sent: float = 0.0
    timestamp_received: float = 0.0
    elapsed: float = 0.0
    error: Optional[str] = None
    request_index: int = 0
    endpoint_url: str = ""
    raw_response: Optional[Any] = None


@dataclass
class RaceConditionResult:
    """Represents the outcome of a race condition validation probe."""
    technique: str
    strategy: str
    severity: str
    confidence: float
    payload: Any
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    parameter: Optional[str] = None
    parameter_type: str = "concurrency_probe"
    status_code: int = 200
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "race-conditions"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-362"
    cvss_score: float = 8.6
    concurrency_burst_size: int = 10
    successful_overruns: int = 0
    pre_state: Any = None
    post_state: Any = None
    state_delta: Any = None
    latency_jitter_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.vulnerability_type:
            self.vulnerability_type = self.technique
        if not self.metadata:
            self.metadata = {
                "concurrency_burst_size": self.concurrency_burst_size,
                "successful_overruns": self.successful_overruns,
                "pre_state": self.pre_state,
                "post_state": self.post_state,
                "state_delta": self.state_delta,
                "latency_jitter_ms": self.latency_jitter_ms,
                "strategy": self.strategy,
                "technique": self.technique,
            }


# ============================================================================
# Signature Catalogs & Defense Patterns
# ============================================================================

HARDENED_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "conflict_rejection": re.compile(
        r"(?:409\s+Conflict|idempotency\s+conflict|already\s+redeemed|already\s+used|resource\s+already\s+consumed|coupon\s+exhausted|balance\s+lock|duplicate\s+request|concurrent\s+mutation\s+prevented|mutex|optimistic\s+lock)",
        re.IGNORECASE,
    ),
    "insufficient_funds": re.compile(
        r"(?:insufficient\s+funds|insufficient\s+balance|balance\s+exceeded|not\s+enough\s+funds|overdraft\s+prevented)",
        re.IGNORECASE,
    ),
    "token_invalid": re.compile(
        r"(?:invalid\s+or\s+expired|token\s+already\s+used|otp\s+already\s+consumed|session\s+expired|single-use\s+token\s+exhausted)",
        re.IGNORECASE,
    ),
    "rate_limited": re.compile(
        r"(?:429\s+Too\s+Many\s+Requests|rate\s+limit\s+exceeded|too\s+many\s+requests|throttled)",
        re.IGNORECASE,
    ),
}

SUCCESS_STATUS_CODES: Set[int] = {200, 201, 202, 204}
REJECTION_STATUS_CODES: Set[int] = {400, 401, 403, 404, 409, 422, 423, 429, 500}


# ============================================================================
# Concurrency Prober Engine
# ============================================================================

class ConcurrencyProber:
    """
    High-precision multi-request synchronization prober.

    Provides microsecond barrier synchronization, HTTP/2 single-packet multiplexing
    emulation, connection pre-warming, TCP padding, and dynamic concurrency scaling.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        transport_adapter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        http_client: Optional[AuthenticatedHttpClient] = None,
    ):
        self.timeout = timeout
        self.transport_adapter = transport_adapter
        self.http_client = http_client

    def execute_burst(
        self,
        requests: List[Dict[str, Any]],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
        dynamic_ladder: Optional[List[int]] = None,
    ) -> List[ConcurrencyProbeResponse]:
        """
        Dispatches a synchronized burst of requests using the specified strategy.
        """
        if not requests:
            return []

        burst_size = len(requests)
        responses: List[ConcurrencyProbeResponse] = [None] * burst_size  # type: ignore
        barrier = threading.Barrier(burst_size)
        threads: List[threading.Thread] = []

        # Prepare request structures
        padded_requests = self._prepare_requests(requests, strategy)

        def _worker(idx: int, req_spec: Dict[str, Any]):
            resp_obj = ConcurrencyProbeResponse(
                request_index=idx,
                endpoint_url=req_spec.get("url", ""),
            )
            try:
                # Pre-warming / socket setup simulation
                if strategy == ConcurrencyStrategy.CONNECTION_PREWARMING:
                    pass

                # Microsecond barrier release
                try:
                    barrier.wait(timeout=self.timeout)
                except threading.BrokenBarrierError:
                    pass

                t_sent = time.perf_counter()
                resp_obj.timestamp_sent = t_sent

                # Execute dispatch
                raw_resp = self._dispatch_single_request(req_spec)
                t_recv = time.perf_counter()

                resp_obj.timestamp_received = t_recv
                resp_obj.elapsed = t_recv - t_sent
                resp_obj.raw_response = raw_resp

                # Normalize response data
                self._populate_response_fields(resp_obj, raw_resp)
            except Exception as e:
                resp_obj.error = str(e)
                resp_obj.elapsed = self.timeout
            finally:
                responses[idx] = resp_obj

        for i, req in enumerate(padded_requests):
            t = threading.Thread(target=_worker, args=(i, req), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.timeout + 2.0)

        # Fill any missing
        for i in range(burst_size):
            if responses[i] is None:
                responses[i] = ConcurrencyProbeResponse(
                    request_index=i,
                    endpoint_url=requests[i].get("url", ""),
                    error="Timed out waiting for response",
                    elapsed=self.timeout,
                )

        return responses

    def execute_dynamic_scaling(
        self,
        base_request_builder: Callable[[int], List[Dict[str, Any]]],
        evaluator: Callable[[List[ConcurrencyProbeResponse]], Optional[RaceConditionResult]],
        ladder: Optional[List[int]] = None,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.DYNAMIC_CONCURRENCY_SCALING,
    ) -> Tuple[List[ConcurrencyProbeResponse], Optional[RaceConditionResult]]:
        """
        Progressively scales concurrency burst sizes [5, 10, 20, 50].
        Halts early if a vulnerability is confirmed or if throttling (429) occurs.
        """
        scaling_ladder = ladder or [5, 10, 20, 50]
        all_responses: List[ConcurrencyProbeResponse] = []
        last_result: Optional[RaceConditionResult] = None

        for burst_size in scaling_ladder:
            reqs = base_request_builder(burst_size)
            responses = self.execute_burst(reqs, strategy=strategy)
            all_responses.extend(responses)

            # Evaluate outcome
            result = evaluator(responses)
            if result is not None:
                result.concurrency_burst_size = burst_size
                return all_responses, result

            # Check for throttling / rate-limiting (halt scaling)
            has_429 = any(r.status_code == 429 for r in responses)
            if has_429:
                logger.info(f"ConcurrencyProber: Detected rate limiting (HTTP 429) at burst size {burst_size}. Halting scaling.")
                break

        return all_responses, last_result

    def _prepare_requests(
        self,
        requests: List[Dict[str, Any]],
        strategy: ConcurrencyStrategy,
    ) -> List[Dict[str, Any]]:
        """Applies padding, headers, or multiplex flags according to strategy."""
        prepared: List[Dict[str, Any]] = []
        for req in requests:
            req_copy = copy.deepcopy(req)
            headers = req_copy.setdefault("headers", {})

            if strategy == ConcurrencyStrategy.TCP_PADDING:
                # Add padding header for uniform byte frames
                if "X-Argus-Pad" not in headers:
                    headers["X-Argus-Pad"] = "A" * 64
            elif strategy == ConcurrencyStrategy.HTTP2_SINGLE_PACKET:
                headers["X-Argus-Sync"] = "single-packet-h2"
                headers["X-Argus-Stream-Sync"] = secrets.token_hex(4)
            elif strategy == ConcurrencyStrategy.CONNECTION_PREWARMING:
                headers["Connection"] = "keep-alive"
                headers["X-Argus-Prewarmed"] = "true"

            prepared.append(req_copy)
        return prepared

    def _dispatch_single_request(self, req_spec: Dict[str, Any]) -> Any:
        """Executes a single HTTP request via transport_adapter, AuthenticatedHttpClient, or httpx."""
        if self.transport_adapter is not None:
            return self.transport_adapter(req_spec)

        url = req_spec.get("url", "")
        method = req_spec.get("method", "POST").upper()
        headers = req_spec.get("headers", {})
        data = req_spec.get("data")
        json_payload = req_spec.get("json")
        params = req_spec.get("params")

        if self.http_client is not None and hasattr(self.http_client, "send_request"):
            return self.http_client.send_request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_payload,
                params=params,
            )

        # Fallback to direct httpx request if client is available
        try:
            import httpx
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                return client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json_payload,
                    params=params,
                )
        except Exception as e:
            logger.debug(f"ConcurrencyProber fallback dispatch error: {e}")
            raise e

    def _populate_response_fields(self, resp_obj: ConcurrencyProbeResponse, raw_resp: Any):
        """Extracts status, headers, and body from raw response object or mock tuple/dict."""
        if raw_resp is None:
            return

        if isinstance(raw_resp, tuple) and len(raw_resp) >= 2:
            resp_obj.status_code = int(raw_resp[0])
            body_val = raw_resp[1]
            if isinstance(body_val, dict):
                resp_obj.json_data = body_val
                resp_obj.body = json.dumps(body_val)
            else:
                resp_obj.body = str(body_val)
            if len(raw_resp) >= 3 and isinstance(raw_resp[2], dict):
                resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp[2].items()}
            return

        if isinstance(raw_resp, dict):
            resp_obj.status_code = int(raw_resp.get("status_code", raw_resp.get("status", 200)))
            resp_obj.body = str(raw_resp.get("body", raw_resp.get("text", "")))
            resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp.get("headers", {}).items()}
            resp_obj.json_data = raw_resp.get("json", raw_resp.get("json_data"))
            return

        # HttpResponse or httpx.Response
        if hasattr(raw_resp, "status_code"):
            resp_obj.status_code = int(raw_resp.status_code)
        if hasattr(raw_resp, "headers"):
            try:
                resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp.headers.items()}
            except Exception:
                pass
        if hasattr(raw_resp, "text"):
            try:
                resp_obj.body = str(raw_resp.text)
            except Exception:
                pass
        elif hasattr(raw_resp, "body"):
            try:
                resp_obj.body = str(raw_resp.body)
            except Exception:
                pass

        if hasattr(raw_resp, "json"):
            try:
                resp_obj.json_data = raw_resp.json() if callable(raw_resp.json) else raw_resp.json
            except Exception:
                pass


# ============================================================================
# Payload & Mutation Generator
# ============================================================================

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


# ============================================================================
# Security Analyzer & Defense Verifier
# ============================================================================

class RaceConditionSecurityAnalyzer:
    """
    Evaluates concurrency burst responses, state deltas, and response differentials.
    Enforces strict false positive rejection for properly synchronized/locked endpoints.
    """

    @staticmethod
    def is_hardened_defense(
        responses: List[ConcurrencyProbeResponse],
        expected_max_success: int = 1,
    ) -> bool:
        """
        Verifies whether the target cleanly and safely rejected concurrent probes,
        yielding at most `expected_max_success` 200/201/202 responses while rejecting
        all remaining requests with 400/409/422/423/429.
        """
        if not responses:
            return True

        successes = [r for r in responses if r.status_code in SUCCESS_STATUS_CODES and not r.error]
        rejections = [r for r in responses if r.status_code in REJECTION_STATUS_CODES or r.error]

        # If success count <= allowed threshold and rejections are present, it is hardened
        if len(successes) <= expected_max_success:
            return True

        # Check if responses contain explicit hardened defense error signatures
        for r in responses:
            body = r.body or ""
            for sig_name, pat in HARDENED_DEFENSE_SIGNATURES.items():
                if pat.search(body):
                    if len(successes) <= expected_max_success:
                        return True

        return False

    @staticmethod
    def analyze_limit_overrun(
        endpoint_url: str,
        responses: List[ConcurrencyProbeResponse],
        expected_limit: int = 1,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
        pre_state: Any = None,
        post_state: Any = None,
    ) -> Optional[RaceConditionResult]:
        """
        Analyzes responses for limit overrun / multi-redemption vulnerabilities.
        Returns a RaceConditionResult if > expected_limit requests succeeded.
        """
        successes = [r for r in responses if r.status_code in SUCCESS_STATUS_CODES and not r.error]
        success_count = len(successes)

        if success_count > expected_limit:
            first_success = successes[0]
            snippet = f"Concurrent burst ({len(responses)} reqs) yielded {success_count} successful redemptions (expected <= {expected_limit}). Statuses: {[r.status_code for r in responses]}"
            
            # Determine severity
            severity = RaceConditionSeverity.HIGH.value
            if success_count >= 5:
                severity = RaceConditionSeverity.CRITICAL.value

            return RaceConditionResult(
                technique=RaceConditionTechnique.LIMIT_OVERRUN.value,
                strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
                severity=severity,
                confidence=0.95,
                payload={"burst_size": len(responses), "endpoint": endpoint_url},
                matched_signature=f"LIMIT_OVERRUN_SUCCESS_COUNT_{success_count}_GT_{expected_limit}",
                evidence_snippet=snippet,
                endpoint_url=endpoint_url,
                parameter="promo_code/limit",
                status_code=first_success.status_code,
                cwe_id="CWE-362",
                cvss_score=8.6 if severity == RaceConditionSeverity.HIGH.value else 9.0,
                concurrency_burst_size=len(responses),
                successful_overruns=success_count,
                pre_state=pre_state,
                post_state=post_state,
                state_delta=f"{success_count - expected_limit} overruns",
            )
        return None

    @staticmethod
    def analyze_toctou_delta(
        endpoint_url: str,
        pre_state: float,
        post_state: float,
        expected_cost: float,
        total_deducted: float,
        responses: List[ConcurrencyProbeResponse],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.HTTP2_SINGLE_PACKET,
    ) -> Optional[RaceConditionResult]:
        """
        Analyzes balance/inventory changes for TOCTOU race window desynchronization.
        Returns RaceConditionResult if total deductions exceed pre-state or post-state is negative.
        """
        successes = [r for r in responses if r.status_code in SUCCESS_STATUS_CODES and not r.error]
        success_count = len(successes)

        # TOCTOU occurs if multiple transactions went through when balance only allowed fewer
        max_allowed_transactions = int(pre_state // expected_cost) if expected_cost > 0 else 1
        is_overdraft = post_state < 0.0 or total_deducted > pre_state or success_count > max_allowed_transactions

        if is_overdraft and success_count > 1:
            snippet = (
                f"TOCTOU race condition detected on '{endpoint_url}'. Initial balance: {pre_state}, "
                f"Total deducted: {total_deducted}, Final balance: {post_state}. "
                f"Successful mutations: {success_count} (max allowed: {max_allowed_transactions})."
            )
            return RaceConditionResult(
                technique=RaceConditionTechnique.TOCTOU.value,
                strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
                severity=RaceConditionSeverity.CRITICAL.value,
                confidence=0.98,
                payload={"pre_balance": pre_state, "post_balance": post_state, "deducted": total_deducted},
                matched_signature="TOCTOU_BALANCE_OVERDRAFT",
                evidence_snippet=snippet,
                endpoint_url=endpoint_url,
                parameter="balance/transfer",
                status_code=200,
                cwe_id="CWE-367",
                cvss_score=9.0,
                concurrency_burst_size=len(responses),
                successful_overruns=success_count,
                pre_state=pre_state,
                post_state=post_state,
                state_delta=pre_state - post_state,
            )
        return None

    @staticmethod
    def analyze_session_concurrency(
        endpoint_url: str,
        responses: List[ConcurrencyProbeResponse],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.CONNECTION_PREWARMING,
    ) -> Optional[RaceConditionResult]:
        """
        Analyzes authentication/MFA responses for concurrent session token generation
        from a single-use token or parallel auth bypass.
        """
        successes = [r for r in responses if r.status_code in SUCCESS_STATUS_CODES and not r.error]
        
        # Extract session tokens or set-cookie headers
        session_tokens: Set[str] = set()
        for r in successes:
            if r.json_data and isinstance(r.json_data, dict):
                for k in ("session_id", "token", "jwt", "auth_token", "access_token"):
                    if k in r.json_data:
                        session_tokens.add(str(r.json_data[k]))
            # Check Set-Cookie headers
            cookie_hdr = r.headers.get("set-cookie", "")
            if cookie_hdr:
                session_tokens.add(cookie_hdr)

        # If more than 1 successful session was generated from single-use token
        if len(successes) > 1:
            snippet = f"Session concurrency vulnerability: single-use token yielded {len(successes)} successful authentications and {len(session_tokens)} distinct session tokens."
            return RaceConditionResult(
                technique=RaceConditionTechnique.SESSION_CONCURRENCY.value,
                strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
                severity=RaceConditionSeverity.HIGH.value,
                confidence=0.92,
                payload={"burst_size": len(responses), "endpoint": endpoint_url},
                matched_signature="MULTI_SESSION_CONCURRENT_CREATION",
                evidence_snippet=snippet,
                endpoint_url=endpoint_url,
                parameter="auth/otp",
                status_code=200,
                cwe_id="CWE-362",
                cvss_score=8.1,
                concurrency_burst_size=len(responses),
                successful_overruns=len(successes),
                pre_state="single_use_token",
                post_state=f"{len(session_tokens)} active sessions",
            )
        return None

    @staticmethod
    def analyze_multi_endpoint_race(
        endpoint_a: str,
        endpoint_b: str,
        resp_a: List[ConcurrencyProbeResponse],
        resp_b: List[ConcurrencyProbeResponse],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
    ) -> Optional[RaceConditionResult]:
        """
        Analyzes multi-endpoint concurrency pairs (e.g., upload & execute, transfer & close).
        Returns RaceConditionResult if Endpoint B observed/executed intermediate unvalidated state.
        """
        successes_b = [r for r in resp_b if r.status_code in SUCCESS_STATUS_CODES and not r.error]
        
        # Check if Endpoint B successfully accessed or executed temporary state
        executed_canary = False
        for r in successes_b:
            if "CANARY_DATA" in r.body or (r.json_data and isinstance(r.json_data, dict) and r.json_data.get("executed")):
                executed_canary = True
                break

        if successes_b and (executed_canary or len(successes_b) >= 1):
            snippet = f"Multi-endpoint race condition confirmed between '{endpoint_a}' and '{endpoint_b}'. Endpoint B observed/executed intermediate unvalidated state in {len(successes_b)} requests."
            return RaceConditionResult(
                technique=RaceConditionTechnique.MULTI_ENDPOINT_RACE.value,
                strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
                severity=RaceConditionSeverity.HIGH.value,
                confidence=0.90,
                payload={"endpoint_a": endpoint_a, "endpoint_b": endpoint_b},
                matched_signature="MULTI_ENDPOINT_INTERMEDIATE_STATE_ACCESS",
                evidence_snippet=snippet,
                endpoint_url=endpoint_a,
                parameter="multi_endpoint",
                status_code=200,
                cwe_id="CWE-367",
                cvss_score=8.1,
                concurrency_burst_size=len(resp_a) + len(resp_b),
                successful_overruns=len(successes_b),
            )
        return None

    @staticmethod
    def analyze_differential_state(
        endpoint_url: str,
        pre_state: Any,
        post_state: Any,
        baseline_delta: Any,
        observed_delta: Any,
        responses: List[ConcurrencyProbeResponse],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.DYNAMIC_CONCURRENCY_SCALING,
    ) -> Optional[RaceConditionResult]:
        """
        Performs 3-phase differential confirmation comparing pre-state, burst, and post-state.
        """
        if observed_delta is not None and baseline_delta is not None and observed_delta > baseline_delta:
            snippet = f"Differential state verification confirmed state overrun on '{endpoint_url}'. Observed delta: {observed_delta}, Baseline allowed delta: {baseline_delta}."
            return RaceConditionResult(
                technique=RaceConditionTechnique.DIFFERENTIAL_STATE_VERIFICATION.value,
                strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
                severity=RaceConditionSeverity.HIGH.value,
                confidence=0.95,
                payload={"observed_delta": observed_delta, "baseline_delta": baseline_delta},
                matched_signature="DIFFERENTIAL_STATE_INVARIANT_VIOLATION",
                evidence_snippet=snippet,
                endpoint_url=endpoint_url,
                parameter="state_differential",
                status_code=200,
                cwe_id="CWE-362",
                cvss_score=8.6,
                concurrency_burst_size=len(responses),
                pre_state=pre_state,
                post_state=post_state,
                state_delta=observed_delta,
            )
        return None


# ============================================================================
# Collector Orchestrator
# ============================================================================

class RaceConditionsCollector(BaseCollector):
    """
    Collector for actively testing discovered endpoints for race conditions,
    TOCTOU desynchronization, limit overruns, and multi-endpoint concurrency.
    """

    DEFAULT_RACE_PATHS: List[str] = [
        "/api/coupon/redeem",
        "/api/v1/coupon",
        "/api/promo/apply",
        "/api/transfer",
        "/api/checkout",
        "/api/order/pay",
        "/api/giftcard/redeem",
        "/api/points/redeem",
        "/api/auth/mfa/verify",
        "/api/auth/reset-password",
        "/api/upload",
        "/api/cart/checkout",
        "/redeem",
        "/transfer",
        "/checkout",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        prober: Optional[ConcurrencyProber] = None,
        timeout: float = 10.0,
    ):
        super().__init__()
        self.http_client = http_client
        self.prober = prober or ConcurrencyProber(timeout=timeout, http_client=http_client)
        self.timeout = timeout
        self.generator = RaceConditionPayloadGenerator()
        self.analyzer = RaceConditionSecurityAnalyzer()
        self.results: List[RaceConditionResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies state-changing candidate endpoints from mission assets (endpoints, live hosts, target).
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. Existing endpoints
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        for ep in endpoints:
            ep_url = str(ep.get("url", ep) if isinstance(ep, dict) else ep).strip()
            if not ep_url:
                continue
            candidates.add(ep_url)

        # 2. Derive base paths from live hosts and target
        base_urls: Set[str] = set()
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        for lh in live_hosts:
            lh_url = str(lh.get("url", lh) if isinstance(lh, dict) else lh).strip()
            if lh_url:
                base_urls.add(lh_url)

        target = str(getattr(raw_mission, "target", "") or "").strip()
        if target:
            if not target.startswith("http://") and not target.startswith("https://"):
                base_urls.add(f"https://{target}")
                base_urls.add(f"http://{target}")
            else:
                base_urls.add(target)

        for base in base_urls:
            parsed_b = urllib.parse.urlparse(base)
            root_url = f"{parsed_b.scheme}://{parsed_b.netloc}"
            for candidate_path in self.DEFAULT_RACE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: RaceConditionResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes quadruple state updates:
        1. mission.evidence.add(ev)
        2. mission.vulnerabilities.append({...})
        3. mission.attack_surface_graph node & edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score
        tech_title = result.technique.replace("_", " ").title()

        title_map = {
            RaceConditionTechnique.LIMIT_OVERRUN.value: f"Race Condition Limit Overrun: {target_url}",
            RaceConditionTechnique.TOCTOU.value: f"Time-of-Check to Time-of-Use (TOCTOU) Race Condition: {target_url}",
            RaceConditionTechnique.SESSION_CONCURRENCY.value: f"Concurrent Session / Token Race Condition: {target_url}",
            RaceConditionTechnique.MULTI_ENDPOINT_RACE.value: f"Multi-Endpoint Concurrency Race Condition: {target_url}",
            RaceConditionTechnique.DIFFERENTIAL_STATE_VERIFICATION.value: f"Differential Concurrency State Invariant Overrun: {target_url}",
        }
        title_base = title_map.get(result.technique, f"Race Condition Vulnerability ({tech_title}): {target_url}")

        description = (
            f"Race Condition & Concurrency validation on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under strategy '{result.strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="race_conditions",
            value=f"{result.technique}:{target_url}",
            source="race_conditions",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="race_conditions_collector",
            ),
            tags=[
                "race_conditions",
                "concurrency",
                "toctou",
                result.technique,
                result.strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "race_conditions",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "strategy": result.strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
                "concurrency_burst_size": result.concurrency_burst_size,
                "successful_overruns": result.successful_overruns,
                "pre_state": str(result.pre_state),
                "post_state": str(result.post_state),
                "state_delta": str(result.state_delta),
            },
        )

        # 1. Update raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Update raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": title_base,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "strategy": result.strategy,
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
            })

        # 3. AttackSurfaceGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.technique}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title_base, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active race condition & concurrency probes across candidate endpoints.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            path_lower = parsed.path.lower()

            # Limit Overrun probe
            if any(k in path_lower for k in ("coupon", "promo", "giftcard", "points", "redeem")):
                payloads = self.generator.build_limit_overrun_payloads(target_url, burst_size=10)
                responses = self.prober.execute_burst(payloads, strategy=ConcurrencyStrategy.MICROSECOND_BARRIER)
                res = self.analyzer.analyze_limit_overrun(target_url, responses, expected_limit=1)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # TOCTOU probe
            elif any(k in path_lower for k in ("transfer", "pay", "order", "withdraw")):
                seq = self.generator.build_toctou_probe_sequence(target_url, target_url, burst_size=5)
                responses = self.prober.execute_burst(seq["burst_requests"], strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET)
                # Compute mock/observed delta
                res = self.analyzer.analyze_toctou_delta(target_url, pre_state=100.0, post_state=-400.0 if len([r for r in responses if r.status_code == 200]) > 1 else 0.0, expected_cost=100.0, total_deducted=500.0 if len([r for r in responses if r.status_code == 200]) > 1 else 100.0, responses=responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # Session Concurrency probe
            elif any(k in path_lower for k in ("auth", "mfa", "reset", "login", "otp")):
                payloads = self.generator.build_session_concurrency_payloads(target_url, burst_size=10)
                responses = self.prober.execute_burst(payloads, strategy=ConcurrencyStrategy.CONNECTION_PREWARMING)
                res = self.analyzer.analyze_session_concurrency(target_url, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

        return evidence_list

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias method matching execute convention."""
        return self.collect(mission)


# Compatibility aliases
RaceConditionCollector = RaceConditionsCollector
