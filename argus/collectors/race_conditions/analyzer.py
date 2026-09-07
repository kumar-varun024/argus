"""race_conditions: Response analysis."""
from __future__ import annotations

from typing import Any, List, Optional, Set

from argus.collectors.race_conditions.models import ConcurrencyProbeResponse, ConcurrencyStrategy, HARDENED_DEFENSE_SIGNATURES, REJECTION_STATUS_CODES, RaceConditionResult, RaceConditionSeverity, RaceConditionTechnique, SUCCESS_STATUS_CODES


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
