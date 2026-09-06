"""business_logic: Response analysis."""
from __future__ import annotations

import re
from typing import Any, List, Optional

from argus.collectors.business_logic.models import BusinessLogicMutationStrategy, BusinessLogicProbe, BusinessLogicProbeResponse, BusinessLogicResult, BusinessLogicSeverity, BusinessLogicTechnique, WorkflowSequence


class BusinessLogicSecurityAnalyzer:
    """
    Pure / deterministic security analyzer evaluating HTTP responses, JSON states,
    and business rule invariants against business logic flaw signatures.
    Strictly suppresses false positives against hardened endpoints.
    """

    # Signatures indicating explicit server-side defense rejection
    HARDENED_ERROR_PATTERNS = [
        re.compile(r"invalid\s+(price|quantity|amount|total|currency)", re.IGNORECASE),
        re.compile(r"(quantity|price|amount)\s+must\s+be\s+(positive|greater\s+than\s+0|valid)", re.IGNORECASE),
        re.compile(r"(negative|zero)\s+(price|quantity|amount|total)\s+(not\s+allowed|invalid|rejected)", re.IGNORECASE),
        re.compile(r"(unauthorized|forbidden|not\s+allowed|permission\s+denied)", re.IGNORECASE),
        re.compile(r"(coupon|voucher|promo)\s+(already\s+used|invalid|expired|not\s+combinable|already\s+applied)", re.IGNORECASE),
        re.compile(r"(cannot\s+combine|single\s+use|max\s+discount\s+exceeded)", re.IGNORECASE),
        re.compile(r"(step\s+missing|invalid\s+step|out\s+of\s+sequence|payment\s+required|unpaid)", re.IGNORECASE),
        re.compile(r"(order\s+not\s+found|cart\s+empty|state\s+mismatch|transition\s+invalid)", re.IGNORECASE),
        re.compile(r"(schema\s+validation|validation\s+error|field\s+disallowed|unknown\s+field)", re.IGNORECASE),
        re.compile(r"(missing\s+required\s+token|csrf\s+token\s+invalid|bad\s+request)", re.IGNORECASE),
    ]

    @classmethod
    def is_hardened_defense(cls, status_code: int, body: str) -> bool:
        """
        Determines if the server response represents an explicit security or
        validation rejection (e.g. 400 Bad Request, 403 Forbidden, 409 Conflict,
        422 Unprocessable Entity, or standard server-side validation error message).
        """
        if status_code in (400, 401, 403, 404, 405, 409, 422, 423, 429):
            return True

        if not body:
            return False

        for pattern in cls.HARDENED_ERROR_PATTERNS:
            if pattern.search(body):
                return True

        return False

    @classmethod
    def analyze_price_tampering(
        cls,
        endpoint_url: str,
        probe: BusinessLogicProbe,
        response: BusinessLogicProbeResponse,
        pre_state: Any = None,
        post_state: Any = None,
    ) -> Optional[BusinessLogicResult]:
        """
        Analyzes responses for price, quantity, currency tampering or zero-amount checkout.
        """
        if cls.is_hardened_defense(response.status_code, response.body):
            return None

        # Must have accepted request (200, 201, 204)
        if response.status_code not in (200, 201, 204):
            return None

        body_str = response.body
        json_obj = response.json_data if isinstance(response.json_data, dict) else {}
        tampered_param = probe.metadata.get("parameter", "price")
        tampered_val = probe.metadata.get("tampered_value", None)

        # Extract numeric total and item price from response if present
        resp_total = None
        for key in ("total", "cart_total", "amount", "order_total", "balance", "total_price", "grand_total"):
            if key in json_obj and isinstance(json_obj[key], (int, float)) and not isinstance(json_obj[key], bool):
                resp_total = json_obj[key]
                break

        resp_item_price = None
        for key in (tampered_param, "unit_price", "item_price", "price"):
            if key in json_obj and isinstance(json_obj[key], (int, float)) and not isinstance(json_obj[key], bool):
                resp_item_price = json_obj[key]
                break

        if resp_item_price is None and isinstance(json_obj.get("items"), list) and json_obj["items"]:
            first_item = json_obj["items"][0]
            if isinstance(first_item, dict):
                for key in (tampered_param, "unit_price", "item_price", "price"):
                    if key in first_item and isinstance(first_item[key], (int, float)) and not isinstance(first_item[key], bool):
                        resp_item_price = first_item[key]
                        break

        # Check for success indicators
        is_success = False
        evidence_snippet = ""
        matched_sig = ""

        # Negative price/amount accepted
        if tampered_val is not None and isinstance(tampered_val, (int, float)) and tampered_val < 0:
            if resp_total is not None and resp_total <= 0:
                is_success = True
                matched_sig = f"negative_{tampered_param}_accepted"
                evidence_snippet = f"Server accepted negative {tampered_param}={tampered_val} resulting in total={resp_total} (HTTP {response.status_code}): {body_str[:150]}"
            elif resp_item_price is not None and (resp_item_price == tampered_val or resp_item_price < 0):
                is_success = True
                matched_sig = f"negative_{tampered_param}_accepted"
                evidence_snippet = f"Server accepted negative {tampered_param}={tampered_val} in item price={resp_item_price} (HTTP {response.status_code}): {body_str[:150]}"
            elif resp_total is None and resp_item_price is None:
                if f"-{abs(tampered_val)}" in body_str or f"-${abs(tampered_val)}" in body_str:
                    is_success = True
                    matched_sig = f"negative_{tampered_param}_accepted"
                    evidence_snippet = f"Server accepted negative {tampered_param}={tampered_val} (HTTP {response.status_code}): {body_str[:150]}"

        # Zero amount checkout accepted
        elif tampered_val == 0 or tampered_val == 0.0 or tampered_val == "0":
            if resp_total is not None:
                if resp_total <= 0:
                    is_success = True
                    matched_sig = f"zero_amount_{tampered_param}_checkout"
                    evidence_snippet = f"Server processed zero-amount checkout with total={resp_total} (HTTP {response.status_code}): {body_str[:150]}"
            elif resp_item_price is not None and resp_item_price == 0:
                is_success = True
                matched_sig = f"zero_amount_{tampered_param}_checkout"
                evidence_snippet = f"Server processed zero-amount checkout with item price=0 (HTTP {response.status_code}): {body_str[:150]}"
            elif resp_total is None and resp_item_price is None:
                if "zero-amount" in body_str.lower() or "free order" in body_str.lower() or "$0.00" in body_str:
                    is_success = True
                    matched_sig = f"zero_amount_{tampered_param}_checkout"
                    evidence_snippet = f"Server processed zero-amount checkout with {tampered_param}=0 (HTTP {response.status_code}): {body_str[:150]}"

        # Type juggling schema tampering (e.g. price=[0] or string 0) accepted
        elif probe.mutation_strategy == BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING:
            if resp_total is not None and resp_total <= 0:
                is_success = True
                matched_sig = f"type_juggling_{tampered_param}_accepted"
                evidence_snippet = f"Server accepted type-juggled {tampered_param}={tampered_val} resulting in total={resp_total} (HTTP {response.status_code}): {body_str[:150]}"
            elif resp_item_price is not None and resp_item_price <= 0:
                is_success = True
                matched_sig = f"type_juggling_{tampered_param}_accepted"
                evidence_snippet = f"Server accepted type-juggled {tampered_param}={tampered_val} (HTTP {response.status_code}): {body_str[:150]}"

        # Parameter pollution accepted
        elif probe.mutation_strategy == BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE:
            if resp_total is not None and resp_total <= 0:
                is_success = True
                matched_sig = "parameter_pollution_duplicate_precedence"
                evidence_snippet = f"Server processed parameter pollution request resulting in total={resp_total} (HTTP {response.status_code}): {body_str[:150]}"
            elif tampered_val is not None and isinstance(tampered_val, (int, float)) and resp_total == tampered_val:
                is_success = True
                matched_sig = "parameter_pollution_duplicate_precedence"
                evidence_snippet = f"Server accepted polluted parameter value {tampered_val} in total (HTTP {response.status_code}): {body_str[:150]}"

        if is_success:
            severity = BusinessLogicSeverity.CRITICAL.value if (tampered_val is not None and isinstance(tampered_val, (int, float)) and tampered_val <= 0) else BusinessLogicSeverity.HIGH.value
            cvss_score = 9.8 if severity == BusinessLogicSeverity.CRITICAL.value else 8.6
            return BusinessLogicResult(
                technique=BusinessLogicTechnique.PRICE_TAMPERING.value,
                strategy=str(probe.mutation_strategy),
                severity=severity,
                confidence=0.98,
                payload=probe.json_data or probe.data or probe.params,
                matched_signature=matched_sig,
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter=tampered_param,
                status_code=response.status_code,
                cwe_id="CWE-602",
                cvss_score=cvss_score,
                pre_state=pre_state,
                post_state=post_state,
            )

        return None

    @classmethod
    def analyze_workflow_step_skip(
        cls,
        endpoint_url: str,
        sequence: WorkflowSequence,
        responses: List[BusinessLogicProbeResponse],
        target_step_name: Optional[str] = None,
    ) -> Optional[BusinessLogicResult]:
        """
        Analyzes responses from an out-of-sequence or step-skipping workflow.
        Detects if final fulfillment or verification was reached without intermediate steps.
        """
        if not responses:
            return None

        final_response = responses[-1]
        if cls.is_hardened_defense(final_response.status_code, final_response.body):
            return None

        # Final step must succeed (200, 201)
        if final_response.status_code not in (200, 201, 204):
            return None

        json_obj = final_response.json_data if isinstance(final_response.json_data, dict) else {}
        body_str = final_response.body

        # Check for unfulfilled / pending / awaiting payment statuses
        status_val = str(json_obj.get("status", "")).lower()
        if status_val in ("pending", "payment_required", "unpaid", "incomplete", "failed", "requires_payment", "awaiting_payment", "rejected", "blocked", "requires_action"):
            return None

        payment_status = str(json_obj.get("payment_status", "")).lower()
        if payment_status in ("pending", "unpaid", "failed", "requires_payment", "awaiting_payment", "requires_action"):
            return None

        # Check body text for explicit pending payment / incomplete workflow indicators
        lower_body = body_str.lower()
        if any(neg in lower_body for neg in ("awaiting payment", "payment required", "payment pending", "cannot fulfill", "unpaid", "step verification failed", "missing step token")):
            return None

        is_success = False
        if (
            status_val in ("success", "completed", "fulfilled", "confirmed")
            or json_obj.get("success") is True
            or json_obj.get("fulfilled") is True
            or "fulfillment_id" in json_obj
            or "tracking_number" in json_obj
            or ("order_id" in json_obj and status_val not in ("pending", "payment_required", "unpaid", "incomplete"))
            or "order fulfilled" in lower_body
            or "order placed" in lower_body
            or "fulfillment confirmed" in lower_body
        ):
            is_success = True

        if is_success:
            trace = [f"{r.step_name}:{r.status_code}" for r in responses]
            skipped_steps = [sequence.steps[i].name for i in sequence.skip_step_indices if i < len(sequence.steps)]
            evidence_snippet = (
                f"Workflow '{sequence.name}' successfully reached fulfillment at '{endpoint_url}' "
                f"while skipping steps: {skipped_steps}. Response (HTTP {final_response.status_code}): {body_str[:150]}"
            )
            return BusinessLogicResult(
                technique=BusinessLogicTechnique.WORKFLOW_STEP_SKIP.value,
                strategy=BusinessLogicMutationStrategy.OUT_OF_SEQUENCE_DISPATCH.value,
                severity=BusinessLogicSeverity.CRITICAL.value,
                confidence=0.98,
                payload={"skipped_steps": skipped_steps, "executed_steps": [r.step_name for r in responses]},
                matched_signature="workflow_intermediate_step_skip_fulfilled",
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter="step_sequence",
                status_code=final_response.status_code,
                cwe_id="CWE-840",
                cvss_score=9.8,
                workflow_trace=trace,
            )

        return None

    @classmethod
    def analyze_mass_assignment(
        cls,
        endpoint_url: str,
        probe: BusinessLogicProbe,
        response: BusinessLogicProbeResponse,
        injected_field: Optional[str] = None,
        injected_val: Optional[Any] = None,
    ) -> Optional[BusinessLogicResult]:
        """
        Analyzes profile/user update responses to detect whether privileged fields
        (e.g., is_admin, role, verified, tier) were accepted and persisted.
        """
        if cls.is_hardened_defense(response.status_code, response.body):
            return None

        if response.status_code not in (200, 201, 204):
            return None

        field_name = injected_field or probe.metadata.get("injected_field", "role")
        field_val = injected_val if injected_val is not None else probe.metadata.get("injected_value", "admin")

        json_obj = response.json_data if isinstance(response.json_data, dict) else {}
        body_str = response.body

        # Check if the privileged field is reflected as assigned/accepted
        is_assigned = False
        if isinstance(json_obj, dict):
            user_data = json_obj.get("user") or json_obj.get("data") or json_obj
            if isinstance(user_data, dict):
                if field_name in user_data:
                    reflected_val = user_data[field_name]
                    # Verify matching or truthy reflection of the injected privileged value
                    if reflected_val == field_val:
                        is_assigned = True
                    elif field_val is True and reflected_val in (True, 1, "true", "True", "admin"):
                        is_assigned = True
                    elif str(field_val).lower() == str(reflected_val).lower() and str(reflected_val).lower() not in ("false", "0", "null", "none", "user", "guest", "member", "customer"):
                        is_assigned = True
                elif field_name == "is_admin" and user_data.get("role") in ("admin", "administrator", "superuser"):
                    is_assigned = True
                elif field_name == "role" and (user_data.get("role") in ("admin", "administrator", "superuser") or user_data.get("is_admin") is True):
                    is_assigned = True

        if not is_assigned:
            # Fallback to precise string reflection of the injected privileged value
            lower_body = body_str.lower()
            if field_val is True and ('"is_admin": true' in lower_body or f'"{field_name}": true' in lower_body or f'"{field_name}": 1' in lower_body):
                is_assigned = True
            elif field_name == "role" and ('"role": "admin"' in lower_body or '"role": "administrator"' in lower_body or '"role": "superuser"' in lower_body):
                is_assigned = True
            elif field_name == "is_admin" and ('"is_admin": true' in lower_body or '"is_admin": 1' in lower_body):
                is_assigned = True
            elif field_val is not None and str(field_val).lower() not in ("false", "0", "null", "none", "user", "guest", "member", "customer") and (
                f'"{field_name}": "{str(field_val).lower()}"' in lower_body
                or f'"{field_name}": {str(field_val).lower()}' in lower_body
            ):
                is_assigned = True

        if is_assigned:
            severity = BusinessLogicSeverity.CRITICAL.value if field_name in ("is_admin", "admin", "is_superuser", "role", "permissions") else BusinessLogicSeverity.HIGH.value
            cvss_score = 9.8 if severity == BusinessLogicSeverity.CRITICAL.value else 8.1
            evidence_snippet = (
                f"Mass assignment parameter injection for privileged field '{field_name}'={field_val} "
                f"was accepted and persisted by server (HTTP {response.status_code}): {body_str[:150]}"
            )
            return BusinessLogicResult(
                technique=BusinessLogicTechnique.MASS_ASSIGNMENT.value,
                strategy=str(probe.mutation_strategy),
                severity=severity,
                confidence=0.96,
                payload=probe.json_data or probe.data or probe.params,
                matched_signature=f"mass_assignment_{field_name}_persisted",
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter=field_name,
                status_code=response.status_code,
                cwe_id="CWE-915",
                cvss_score=cvss_score,
            )

        return None

    @classmethod
    def analyze_coupon_stacking(
        cls,
        endpoint_url: str,
        responses: List[BusinessLogicProbeResponse],
        original_total: float = 100.0,
        final_total: Optional[float] = None,
        discount_applied: Optional[float] = None,
    ) -> Optional[BusinessLogicResult]:
        """
        Analyzes coupon application probes to identify coupon stacking, idempotency abuse,
        or negative cart totals resulting from repeated discount applications.
        """
        if not responses:
            return None

        # Check if all responses were hardened defenses
        successful_responses = [r for r in responses if not cls.is_hardened_defense(r.status_code, r.body) and r.status_code in (200, 201)]
        if not successful_responses:
            return None

        last_resp = successful_responses[-1]
        json_obj = last_resp.json_data if isinstance(last_resp.json_data, dict) else {}
        observed_total = final_total if final_total is not None else json_obj.get("total", json_obj.get("cart_total", json_obj.get("amount", None)))
        observed_discount = discount_applied if discount_applied is not None else json_obj.get("discount", json_obj.get("discount_amount", None))

        # If only 1 successful response, ensure it actually represents a flaw (e.g. negative total or multi-coupon array)
        if len(successful_responses) <= 1:
            tot = observed_total
            if tot is not None and isinstance(tot, (int, float)) and tot < 0:
                pass
            elif isinstance(json_obj.get("applied_coupons"), list) and len(json_obj["applied_coupons"]) > 1:
                pass
            else:
                return None  # Normal single coupon application is legitimate behavior

        is_vulnerable = False
        matched_sig = ""
        evidence_snippet = ""

        # 1. Negative total cart balance
        if observed_total is not None and isinstance(observed_total, (int, float)) and observed_total < 0:
            is_vulnerable = True
            matched_sig = "coupon_stacking_negative_balance"
            evidence_snippet = f"Multiple coupon applications generated a negative total balance: {observed_total} (Original: {original_total})"

        # 2. Explicit discount stack in json
        elif isinstance(json_obj.get("applied_coupons"), list) and len(json_obj["applied_coupons"]) > 1:
            is_vulnerable = True
            matched_sig = "coupon_stacking_multi_code_accepted"
            evidence_snippet = f"Server accepted multiple non-stackable coupons: {json_obj['applied_coupons']}"

        # 3. Cumulative discount exceeding individual coupon value (e.g. 20% applied multiple times -> 60%)
        elif len(successful_responses) > 1 and (
            (observed_discount is not None and isinstance(observed_discount, (int, float)) and observed_discount > 20.0)
            or (observed_total is not None and isinstance(observed_total, (int, float)) and observed_total < original_total * 0.7)
        ):
            is_vulnerable = True
            matched_sig = "coupon_reapplication_idempotency_bypass"
            evidence_snippet = (
                f"Single-use coupon was repeatedly applied {len(successful_responses)} times resulting in cumulative "
                f"discount={observed_discount} / total={observed_total} (Original: {original_total})"
            )

        if is_vulnerable:
            severity = BusinessLogicSeverity.HIGH.value if (observed_total is not None and observed_total >= 0) else BusinessLogicSeverity.CRITICAL.value
            cvss_score = 8.6 if severity == BusinessLogicSeverity.HIGH.value else 9.8
            return BusinessLogicResult(
                technique=BusinessLogicTechnique.COUPON_STACKING.value,
                strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION.value,
                severity=severity,
                confidence=0.95,
                payload={"responses_count": len(responses), "observed_total": observed_total, "observed_discount": observed_discount},
                matched_signature=matched_sig,
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter="coupon_code",
                status_code=last_resp.status_code,
                cwe_id="CWE-799",
                cvss_score=cvss_score,
                pre_state={"original_total": original_total},
                post_state={"final_total": observed_total},
            )

        return None

    @classmethod
    def analyze_differential_state(
        cls,
        endpoint_url: str,
        technique: str,
        strategy: str,
        pre_state: Any,
        post_state: Any,
        expected_post_state: Any,
        response: Optional[BusinessLogicProbeResponse] = None,
    ) -> Optional[BusinessLogicResult]:
        """
        Compares observed pre-state and post-state against the business rule invariant.
        Detects financial balance inconsistencies, privilege escalation state deltas,
        or workflow state violations.
        """
        if response and cls.is_hardened_defense(response.status_code, response.body):
            return None

        # Check for invariant violation
        if post_state == expected_post_state:
            return None  # Invariant held cleanly

        status_code = response.status_code if response else 200
        delta = {"pre_state": pre_state, "post_state": post_state, "expected_post_state": expected_post_state}
        evidence_snippet = (
            f"Differential state invariant violation at '{endpoint_url}': "
            f"Pre-state: {pre_state} -> Post-state: {post_state} (Expected: {expected_post_state})"
        )

        return BusinessLogicResult(
            technique=technique,
            strategy=strategy,
            severity=BusinessLogicSeverity.HIGH.value,
            confidence=0.95,
            payload=delta,
            matched_signature="differential_state_invariant_violation",
            evidence_snippet=evidence_snippet,
            endpoint_url=endpoint_url,
            parameter="state_invariant",
            status_code=status_code,
            cwe_id="CWE-840",
            cvss_score=8.5,
            pre_state=pre_state,
            post_state=post_state,
            state_delta=delta,
        )
