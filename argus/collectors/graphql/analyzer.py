"""graphql: Response analysis."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

from argus.collectors.graphql.models import BATCH_DEFENSE_SIGNATURES, COMMAND_OUTPUT_SIGNATURES, DEPTH_LIMIT_DEFENSE_SIGNATURES, FIELD_SUGGESTION_SIGNATURES, FRAGMENT_CYCLE_DEFENSE_SIGNATURES, GraphQLMutationStrategy, GraphQLSecurityResult, GraphQLSeverity, GraphQLTechnique, HARDENED_INTROSPECTION_SIGNATURES, INTROSPECTION_SIGNATURES, SQL_ERROR_SIGNATURES


class GraphQLSecurityAnalyzer:
    """Analyzes HTTP responses from GraphQL security probes for vulnerability signatures."""

    @staticmethod
    def _parse_response_body(response: Any) -> Tuple[Optional[Dict[str, Any]], str]:
        """Extracts parsed JSON and raw body string from HttpResponse."""
        raw_text = ""
        if hasattr(response, "body") and response.body is not None:
            raw_text = str(response.body)
        elif hasattr(response, "text") and response.text is not None:
            raw_text = str(response.text)
        elif hasattr(response, "content") and response.content is not None:
            try:
                raw_text = response.content.decode("utf-8", errors="replace")
            except Exception:
                raw_text = str(response.content)

        parsed_json: Optional[Dict[str, Any]] = None
        if hasattr(response, "json") and callable(response.json):
            try:
                parsed_json = response.json()
            except Exception:
                pass

        if parsed_json is None and raw_text:
            try:
                parsed_json = json.loads(raw_text)
            except Exception:
                pass

        return parsed_json, raw_text

    @classmethod
    def analyze_introspection(
        cls,
        response: Any,
        baseline_response: Optional[Any] = None,
        technique: str = GraphQLTechnique.INTROSPECTION.value,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether full schema or type introspection data was leaked."""
        status_code = getattr(response, "status_code", 200) or 200
        parsed_json, body = cls._parse_response_body(response)

        # Baseline check
        if baseline_response is not None:
            _, base_body = cls._parse_response_body(baseline_response)
            if body and body == base_body:
                return None

        # Check for hardened server defenses (false positive suppression)
        for sig_name, pat in HARDENED_INTROSPECTION_SIGNATURES.items():
            if pat.search(body):
                return None

        if not parsed_json or not isinstance(parsed_json, dict):
            # Check raw regex if JSON parser failed
            if any(p.search(body) for p in INTROSPECTION_SIGNATURES.values()):
                # Ensure it's not a generic error page
                if status_code in (200, 201) and "types" in body:
                    return GraphQLSecurityResult(
                        technique=technique,
                        mutation_strategy=mutation_strategy,
                        severity=GraphQLSeverity.MEDIUM.value,
                        confidence=0.90,
                        payload=payload,
                        matched_signature="raw_introspection_signature",
                        evidence_snippet=body[:200],
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-introspection",
                    )
            return None

        data = parsed_json.get("data") or {}
        if not isinstance(data, dict):
            return None

        # 1. Full schema introspection check
        schema_obj = data.get("__schema") or data.get("_argus_schema")
        if isinstance(schema_obj, dict):
            types_list = schema_obj.get("types") or schema_obj.get("_argus_types")
            if isinstance(types_list, list) and len(types_list) > 0:
                snippet = json.dumps(schema_obj)[:200]
                has_mutations = bool(
                    schema_obj.get("mutationType") or schema_obj.get("_argus_mt")
                )
                severity = (
                    GraphQLSeverity.HIGH.value
                    if has_mutations and len(types_list) > 5
                    else GraphQLSeverity.MEDIUM.value
                )
                return GraphQLSecurityResult(
                    technique=technique,
                    mutation_strategy=mutation_strategy,
                    severity=severity,
                    confidence=0.95,
                    payload=payload,
                    matched_signature="schema_introspection_types",
                    evidence_snippet=snippet,
                    endpoint_url=endpoint_url,
                    status_code=status_code,
                    template_id="graphql-introspection",
                )

            # QueryType presence
            qt = schema_obj.get("queryType") or schema_obj.get("_argus_qt")
            if isinstance(qt, dict) and qt.get("name"):
                return GraphQLSecurityResult(
                    technique=technique,
                    mutation_strategy=mutation_strategy,
                    severity=GraphQLSeverity.MEDIUM.value,
                    confidence=0.92,
                    payload=payload,
                    matched_signature="schema_introspection_query_type",
                    evidence_snippet=json.dumps(schema_obj)[:200],
                    endpoint_url=endpoint_url,
                    status_code=status_code,
                    template_id="graphql-introspection",
                )

        # 2. Type-specific introspection check (__type)
        type_obj = data.get("__type") or data.get("_argus_type")
        if isinstance(type_obj, dict):
            fields_list = type_obj.get("fields")
            if isinstance(fields_list, list) and len(fields_list) > 0:
                return GraphQLSecurityResult(
                    technique=GraphQLTechnique.TYPE_INTROSPECTION.value,
                    mutation_strategy=mutation_strategy,
                    severity=GraphQLSeverity.MEDIUM.value,
                    confidence=0.92,
                    payload=payload,
                    matched_signature="type_introspection_fields",
                    evidence_snippet=json.dumps(type_obj)[:200],
                    endpoint_url=endpoint_url,
                    status_code=status_code,
                    template_id="graphql-introspection",
                )

        return None

    @classmethod
    def analyze_field_suggestions(
        cls,
        response: Any,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether GraphQL field suggestions ('Did you mean ...?') leak schema information."""
        status_code = getattr(response, "status_code", 200) or 200
        _, body = cls._parse_response_body(response)

        # Baseline check
        if baseline_response is not None:
            _, base_body = cls._parse_response_body(baseline_response)
            if body and body == base_body:
                return None

        # Check for field suggestion signatures
        for sig_name, pat in FIELD_SUGGESTION_SIGNATURES.items():
            m = pat.search(body)
            if m:
                snippet = body[max(0, m.start() - 20) : min(len(body), m.end() + 100)]
                return GraphQLSecurityResult(
                    technique=GraphQLTechnique.FIELD_SUGGESTIONS.value,
                    mutation_strategy=mutation_strategy,
                    severity=GraphQLSeverity.LOW.value,
                    confidence=0.92,
                    payload=payload,
                    matched_signature=f"field_suggestion_{sig_name}",
                    evidence_snippet=snippet,
                    endpoint_url=endpoint_url,
                    status_code=status_code,
                    template_id="graphql-field-suggestions",
                )

        return None

    @classmethod
    def analyze_query_depth(
        cls,
        response: Any,
        depth: int,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether unbounded query depth is executed without complexity limits."""
        status_code = getattr(response, "status_code", 200) or 200
        parsed_json, body = cls._parse_response_body(response)

        # Check if depth defense caught and rejected it (FP suppression)
        for sig_name, pat in DEPTH_LIMIT_DEFENSE_SIGNATURES.items():
            if pat.search(body):
                return None

        # Baseline check
        if baseline_response is not None:
            _, base_body = cls._parse_response_body(baseline_response)
            if body and body == base_body:
                return None

        # Vulnerable execution: HTTP 200 with non-null data payload for depth >= 5
        if status_code in (200, 201) and parsed_json and isinstance(parsed_json, dict):
            data = parsed_json.get("data")
            if data and isinstance(data, dict):
                # Traverse data depth
                def _measure_depth(obj: Any) -> int:
                    if isinstance(obj, dict) and obj:
                        return 1 + max(_measure_depth(v) for v in obj.values())
                    elif isinstance(obj, list) and obj:
                        return 1 + max(_measure_depth(item) for item in obj)
                    return 1

                actual_depth = _measure_depth(data)
                if actual_depth >= depth or (depth >= 5 and "user" in data):
                    severity = (
                        GraphQLSeverity.HIGH.value
                        if depth >= 10
                        else GraphQLSeverity.MEDIUM.value
                    )
                    return GraphQLSecurityResult(
                        technique=GraphQLTechnique.QUERY_DEPTH.value,
                        mutation_strategy=mutation_strategy,
                        severity=severity,
                        confidence=0.90,
                        payload=payload,
                        matched_signature=f"unbounded_depth_{depth}",
                        evidence_snippet=json.dumps(data)[:200],
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-dos",
                    )

        return None

    @classmethod
    def analyze_fragment_recursion(
        cls,
        response: Any,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
        elapsed: float = 0.0,
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether circular fragment recursion causes denial-of-service / crash."""
        status_code = getattr(response, "status_code", 200) or 200
        _, body = cls._parse_response_body(response)

        # Spec-compliant defense (Cannot spread fragment within itself) -> Secure, return None
        for sig_name, pat in FRAGMENT_CYCLE_DEFENSE_SIGNATURES.items():
            if pat.search(body):
                return None

        # If server crashed with 500/502/504 or took > 3.5s to respond -> Vulnerable to recursion DoS
        if status_code in (500, 502, 503, 504) or elapsed >= 3.5:
            return GraphQLSecurityResult(
                technique=GraphQLTechnique.FRAGMENT_RECURSION.value,
                mutation_strategy=mutation_strategy,
                severity=GraphQLSeverity.HIGH.value,
                confidence=0.90,
                payload=payload,
                matched_signature="fragment_recursion_crash_or_delay",
                evidence_snippet=body[:200] if body else f"HTTP {status_code} delay={elapsed:.2f}s",
                endpoint_url=endpoint_url,
                status_code=status_code,
                delay_delta=elapsed,
                template_id="graphql-dos",
            )

        return None

    @classmethod
    def analyze_batching_array(
        cls,
        response: Any,
        batch_size: int = 3,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether HTTP query array batching is executed."""
        status_code = getattr(response, "status_code", 200) or 200
        parsed_json, body = cls._parse_response_body(response)

        # Check for batch defense
        for sig_name, pat in BATCH_DEFENSE_SIGNATURES.items():
            if pat.search(body):
                return None

        # Check if response is a JSON array of response objects
        if status_code in (200, 201) and isinstance(parsed_json, list) and len(parsed_json) >= 2:
            snippet = json.dumps(parsed_json)[:200]
            return GraphQLSecurityResult(
                technique=GraphQLTechnique.BATCHING_ARRAY.value,
                mutation_strategy=mutation_strategy,
                severity=GraphQLSeverity.MEDIUM.value,
                confidence=0.92,
                payload=payload,
                matched_signature="batch_array_response",
                evidence_snippet=snippet,
                endpoint_url=endpoint_url,
                status_code=status_code,
                template_id="graphql-batching",
            )

        return None

    @classmethod
    def analyze_alias_multiplexing(
        cls,
        response: Any,
        alias_count: int = 20,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether alias multiplexing bypassed complexity / rate limits."""
        status_code = getattr(response, "status_code", 200) or 200
        parsed_json, body = cls._parse_response_body(response)

        # Complexity limit rejection -> Secure
        for sig_name, pat in DEPTH_LIMIT_DEFENSE_SIGNATURES.items():
            if pat.search(body):
                return None

        if status_code in (200, 201) and parsed_json and isinstance(parsed_json, dict):
            data = parsed_json.get("data")
            if isinstance(data, dict):
                # Count matched aliases like a1, a2, a3...
                matched_aliases = [k for k in data.keys() if re.match(r"^a\d+$", k)]
                if len(matched_aliases) >= min(5, alias_count // 2):
                    snippet = json.dumps(data)[:200]
                    return GraphQLSecurityResult(
                        technique=GraphQLTechnique.BATCHING_ALIAS.value,
                        mutation_strategy=mutation_strategy,
                        severity=GraphQLSeverity.MEDIUM.value,
                        confidence=0.92,
                        payload=payload,
                        matched_signature="alias_multiplexing_resolved",
                        evidence_snippet=snippet,
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-batching",
                    )

        return None

    @classmethod
    def analyze_field_access_control(
        cls,
        response: Any,
        sensitive_field: str,
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
    ) -> Optional[GraphQLSecurityResult]:
        """Validates whether sensitive/administrative fields leak unauthorized data (BOPLA)."""
        status_code = getattr(response, "status_code", 200) or 200
        parsed_json, body = cls._parse_response_body(response)

        # If HTTP 401/403 or errors say Unauthorized with null data -> Secure
        if status_code in (401, 403):
            return None

        if parsed_json and isinstance(parsed_json, dict):
            data = parsed_json.get("data")
            errors = parsed_json.get("errors") or []

            # If field data is non-null and contains payload
            if isinstance(data, dict) and sensitive_field in data:
                field_val = data.get(sensitive_field)
                if field_val is not None:
                    # Non-null sensitive field access confirmed
                    snippet = json.dumps({sensitive_field: field_val})[:200]
                    return GraphQLSecurityResult(
                        technique=GraphQLTechnique.FIELD_ACCESS_CONTROL.value,
                        mutation_strategy=mutation_strategy,
                        severity=GraphQLSeverity.HIGH.value,
                        confidence=0.95,
                        payload=payload,
                        matched_signature=f"sensitive_field_{sensitive_field}",
                        evidence_snippet=snippet,
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-access-control",
                    )

        return None

    @classmethod
    def analyze_injection(
        cls,
        response: Any,
        injection_type: str = "sqli",
        baseline_response: Optional[Any] = None,
        mutation_strategy: str = GraphQLMutationStrategy.STANDARD.value,
        payload: str = "",
        endpoint_url: str = "",
        elapsed: float = 0.0,
    ) -> Optional[GraphQLSecurityResult]:
        """Validates SQL injection or Command injection in GraphQL arguments."""
        status_code = getattr(response, "status_code", 200) or 200
        _, body = cls._parse_response_body(response)

        # Baseline noise subtraction
        if baseline_response is not None:
            _, base_body = cls._parse_response_body(baseline_response)
            if body and body == base_body:
                return None

        # Echo suppression check: if payload is merely reflected without DB/OS error
        cleaned_body = body
        if payload and payload in cleaned_body:
            cleaned_body = cleaned_body.replace(payload, "")

        if injection_type == "sqli":
            for db_type, pattern in SQL_ERROR_SIGNATURES.items():
                if pattern.search(cleaned_body):
                    m = pattern.search(cleaned_body)
                    snippet = cleaned_body[
                        max(0, m.start() - 20) : min(len(cleaned_body), m.end() + 100)
                    ]
                    return GraphQLSecurityResult(
                        technique=GraphQLTechnique.INJECTION_SQLI.value,
                        mutation_strategy=mutation_strategy,
                        severity=GraphQLSeverity.HIGH.value,
                        confidence=0.98,
                        payload=payload,
                        matched_signature=f"sqli_error_{db_type}",
                        evidence_snippet=snippet,
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-injection-sqli",
                    )

        elif injection_type == "cmdi":
            for cmd_sig, pattern in COMMAND_OUTPUT_SIGNATURES.items():
                if pattern.search(cleaned_body):
                    m = pattern.search(cleaned_body)
                    snippet = cleaned_body[
                        max(0, m.start() - 20) : min(len(cleaned_body), m.end() + 100)
                    ]
                    return GraphQLSecurityResult(
                        technique=GraphQLTechnique.INJECTION_CMDI.value,
                        mutation_strategy=mutation_strategy,
                        severity=GraphQLSeverity.CRITICAL.value,
                        confidence=0.98,
                        payload=payload,
                        matched_signature=f"cmdi_output_{cmd_sig}",
                        evidence_snippet=snippet,
                        endpoint_url=endpoint_url,
                        status_code=status_code,
                        template_id="graphql-injection-cmdi",
                    )

        return None
