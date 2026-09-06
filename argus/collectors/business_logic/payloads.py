"""business_logic: Payload generation."""
from __future__ import annotations

import copy
import urllib.parse
from typing import Any, Dict, List, Optional

from argus.collectors.business_logic.models import BusinessLogicMutationStrategy, BusinessLogicProbe, BusinessLogicTechnique, WorkflowSequence, WorkflowStep


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
