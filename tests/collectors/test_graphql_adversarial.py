"""
Adversarial Stress, Evasion, and Edge-Case Test Suite for GraphQL Security Collector.

Challenger 1: GraphQL Adversarial Evasion Challenge
Covers:
1. Complex nested schema responses with partial null data and malformed JSON payloads.
2. Evasion payloads across method swapping (GET, POST urlencoded), content-type variation,
   comment obfuscation, alias renaming, and directives.
3. False positive rejection against hardened endpoints that return realistic error structures
   (e.g., 400 Bad Request with GraphQL error format, 200 with data: null and errors).
4. Massive or recursive query handling without infinite loops, crashes, or unbounded memory growth.
5. End-to-end multi-mutation evasion verification against evasive/WAF-protected GraphQL servers.
"""
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.graphql import (
    GraphQLSecurityCollector,
    GraphQLCollector,
    GraphQLPayloadGenerator,
    GraphQLSecurityAnalyzer,
    GraphQLSecurityResult,
    GraphQLSeverity,
    GraphQLTechnique,
    GraphQLMutationStrategy,
    INTROSPECTION_SIGNATURES,
    HARDENED_INTROSPECTION_SIGNATURES,
    FIELD_SUGGESTION_SIGNATURES,
    DEPTH_LIMIT_DEFENSE_SIGNATURES,
    FRAGMENT_CYCLE_DEFENSE_SIGNATURES,
    BATCH_DEFENSE_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    COMMAND_OUTPUT_SIGNATURES,
    SENSITIVE_FIELD_NAMES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission


class AdversarialMockGraphQLHttpClient:
    """Configurable mock HTTP client for adversarial GraphQL evasions and boundary tests."""

    def __init__(self):
        self.routes: Dict[str, Tuple[int, str, float]] = {}
        self.method_rules: Dict[str, Dict[str, Tuple[int, str, float]]] = {
            "GET": {},
            "POST": {},
        }
        self.header_rules: Dict[str, Tuple[int, str, float]] = {}
        self.request_history: List[Dict[str, Any]] = []

    def set_route(self, keyword: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[keyword] = (status_code, body, elapsed)

    def set_method_route(self, method: str, keyword: str, status_code: int, body: str, elapsed: float = 0.05):
        self.method_rules[method.upper()][keyword] = (status_code, body, elapsed)

    def set_header_route(self, header_name: str, header_val_sub: str, status_code: int, body: str, elapsed: float = 0.05):
        self.header_rules[f"{header_name.lower()}:{header_val_sub.lower()}"] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.request_history.append({"method": "GET", "url": target_url, "params": params, "headers": headers, "cookies": cookies})

        # Match header rules
        for hk, hv in headers.items():
            for rule_k, rule_v in self.header_rules.items():
                req_hk, req_sub = rule_k.split(":", 1)
                if hk.lower() == req_hk and req_sub in str(hv).lower():
                    return HttpResponse(success=(200 <= rule_v[0] < 300), status_code=rule_v[0], raw_body=rule_v[1], body=rule_v[1], url=target_url, elapsed=rule_v[2])

        # Match method specific GET routes
        query_val = params.get("query", "")
        for k, (sc, b, el) in self.method_rules["GET"].items():
            if k in query_val or k in str(params) or k in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Match general routes
        for k, (sc, b, el) in self.routes.items():
            if k in query_val or k in str(params) or k in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Default clean response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__typename": "Query"}}',
            body='{"data": {"__typename": "Query"}}',
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.request_history.append({"method": "POST", "url": target_url, "data": data, "json": json_data, "headers": headers, "cookies": cookies})

        # Match header rules
        for hk, hv in headers.items():
            for rule_k, rule_v in self.header_rules.items():
                req_hk, req_sub = rule_k.split(":", 1)
                if hk.lower() == req_hk and req_sub in str(hv).lower():
                    return HttpResponse(success=(200 <= rule_v[0] < 300), status_code=rule_v[0], raw_body=rule_v[1], body=rule_v[1], url=target_url, elapsed=rule_v[2])

        payload_str = ""
        if isinstance(data, (bytes, bytearray)):
            payload_str = data.decode("utf-8", errors="ignore")
        elif isinstance(data, str):
            payload_str = data
        elif json_data is not None:
            payload_str = json.dumps(json_data)

        # Match method specific POST routes
        for k, (sc, b, el) in self.method_rules["POST"].items():
            if k in payload_str or k in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Match general routes
        for k, (sc, b, el) in self.routes.items():
            if k in payload_str or k in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__typename": "Query"}}',
            body='{"data": {"__typename": "Query"}}',
            url=target_url,
            elapsed=0.05,
        )


# ============================================================================
# Suite 1: Complex Nested Schema Responses with Partial Null Data
# ============================================================================

class TestAdversarialSchemaParsingAndNulls:
    """Stress tests schema parsing against malformed, partial, null, and adversarial JSON structures."""

    def test_schema_with_null_root_and_empty_types(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Case A: __schema is None
        resp_null = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__schema": null}}',
            body='{"data": {"__schema": null}}',
            url="https://target/graphql",
        )
        assert analyzer.analyze_introspection(resp_null) is None

        # Case B: types is empty list and queryType is None
        resp_empty_types = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__schema": {"types": [], "queryType": null}}}',
            body='{"data": {"__schema": {"types": [], "queryType": null}}}',
            url="https://target/graphql",
        )
        assert analyzer.analyze_introspection(resp_empty_types) is None

        # Case C: types is None
        resp_none_types = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__schema": {"types": null, "queryType": null}}}',
            body='{"data": {"__schema": {"types": null, "queryType": null}}}',
            url="https://target/graphql",
        )
        assert analyzer.analyze_introspection(resp_none_types) is None

    def test_schema_with_heterogeneous_types_and_null_elements(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Types array contains nulls, numbers, empty dicts alongside valid objects
        hetero_schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "types": [
                        None,
                        {},
                        {"name": None, "kind": None},
                        {"name": "User", "kind": "OBJECT", "fields": None},
                        {"name": "Admin", "kind": "OBJECT", "fields": []},
                    ],
                }
            }
        }
        body = json.dumps(hetero_schema)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.matched_signature == "schema_introspection_types"

    def test_schema_with_non_dict_data_payloads(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Test non-dict data representations
        for bad_data in ['{"data": "unexpected string"}', '{"data": 12345}', '{"data": [1, 2, 3]}', '{"data": true}']:
            resp = HttpResponse(success=True, status_code=200, raw_body=bad_data, body=bad_data, url="https://target/graphql")
            assert analyzer.analyze_introspection(resp) is None

    def test_schema_with_unicode_and_special_characters(self):
        analyzer = GraphQLSecurityAnalyzer()
        unicode_schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query_🚀_Ω"},
                    "mutationType": {"name": "Mutation_🔒"},
                    "types": [
                        {"name": f"Type_日本語_{i}", "kind": "OBJECT", "description": "🔐 Secret data: <script>alert(1)</script>"}
                        for i in range(10)
                    ],
                }
            }
        }
        body = json.dumps(unicode_schema)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.severity == GraphQLSeverity.HIGH.value  # has mutation and > 5 types

    def test_type_introspection_with_null_and_empty_fields(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Case A: __type is null
        resp_null = HttpResponse(success=True, status_code=200, raw_body='{"data": {"__type": null}}', body='{"data": {"__type": null}}', url="https://target/graphql")
        assert analyzer.analyze_introspection(resp_null) is None

        # Case B: fields is empty list
        resp_empty = HttpResponse(success=True, status_code=200, raw_body='{"data": {"__type": {"name": "Query", "fields": []}}}', body='{"data": {"__type": {"name": "Query", "fields": []}}}', url="https://target/graphql")
        assert analyzer.analyze_introspection(resp_empty) is None

        # Case C: fields is None
        resp_none = HttpResponse(success=True, status_code=200, raw_body='{"data": {"__type": {"name": "Query", "fields": null}}}', body='{"data": {"__type": {"name": "Query", "fields": null}}}', url="https://target/graphql")
        assert analyzer.analyze_introspection(resp_none) is None

        # Case D: fields has elements
        resp_valid = HttpResponse(success=True, status_code=200, raw_body='{"data": {"__type": {"name": "Query", "fields": [{"name": "profile"}]}}}', body='{"data": {"__type": {"name": "Query", "fields": [{"name": "profile"}]}}}', url="https://target/graphql")
        res = analyzer.analyze_introspection(resp_valid)
        assert res is not None
        assert res.technique == GraphQLTechnique.TYPE_INTROSPECTION.value


# ============================================================================
# Suite 2: Evasion Payloads Across All 6 Mutation Strategies
# ============================================================================

class TestAdversarialMutationStrategies:
    """Stress tests all 6 query mutation and WAF evasion strategies with complex queries and boundary cases."""

    def test_method_swapping_with_variables_and_operations(self):
        gen = GraphQLPayloadGenerator()
        query = 'query GetUserData($userId: ID!) { user(id: $userId) { id email role } }'
        variables = {"userId": "1002", "active": True}
        operation_name = "GetUserData"

        req = gen.mutate_payload(
            query=query,
            strategy=GraphQLMutationStrategy.METHOD_SWAPPING,
            variables=variables,
            operation_name=operation_name,
        )

        assert req["method"] == "GET"
        assert req["params"]["query"] == query
        assert req["params"]["operationName"] == "GetUserData"
        parsed_vars = json.loads(req["params"]["variables"])
        assert parsed_vars["userId"] == "1002"
        assert parsed_vars["active"] is True
        assert req["json"] is None

    def test_content_type_manipulation_variations(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION)
        assert req["method"] == "POST"
        assert req["headers"]["Content-Type"] == "application/graphql"
        assert req["data"] == query
        assert req["json"] is None

    def test_query_obfuscation_with_string_literals_and_nested_braces(self):
        gen = GraphQLPayloadGenerator()
        # Query with argument containing nested braces and spaces
        query = 'query ComplexProbe { search(query: "{admin}") { id title } }'
        req = gen.mutate_payload(query, GraphQLMutationStrategy.QUERY_OBFUSCATION)
        obfuscated = req["json"]["query"]
        assert "# argus_guard" in obfuscated
        assert "# argus_end" in obfuscated
        assert req["method"] == "POST"

    def test_alias_pollution_on_all_introspection_fields(self):
        gen = GraphQLPayloadGenerator()
        query = """query IntrospectAll {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
  __type(name: "Query") { name }
}"""
        req = gen.mutate_payload(query, GraphQLMutationStrategy.ALIAS_POLLUTION)
        polluted = req["json"]["query"]
        assert "_argus_schema: __schema" in polluted
        assert "_argus_types: types" in polluted
        assert "_argus_qt: queryType" in polluted
        assert "_argus_mt: mutationType" in polluted
        assert "_argus_type: __type" in polluted

        # Test that analyzer correctly extracts polluted response
        analyzer = GraphQLSecurityAnalyzer()
        polluted_response_data = {
            "data": {
                "_argus_schema": {
                    "_argus_qt": {"name": "Query"},
                    "_argus_mt": {"name": "Mutation"},
                    "_argus_types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(12)],
                }
            }
        }
        body = json.dumps(polluted_response_data)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, mutation_strategy=GraphQLMutationStrategy.ALIAS_POLLUTION.value)
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.mutation_strategy == GraphQLMutationStrategy.ALIAS_POLLUTION.value
        assert res.severity == GraphQLSeverity.HIGH.value

    def test_variable_extraction_with_multiple_arguments(self):
        gen = GraphQLPayloadGenerator()
        # Query with multiple arguments inside operation
        query = 'query FilterSearch { search(term: "admin\'--", category: "users", tag: "debug") { id } }'
        req = gen.mutate_payload(query, GraphQLMutationStrategy.VARIABLE_EXTRACTION)
        mutated_query = req["json"]["query"]
        vars_dict = req["json"]["variables"]

        assert "$argus_term_1: String" in mutated_query
        assert "$argus_category_2: String" in mutated_query
        assert "$argus_tag_3: String" in mutated_query
        assert vars_dict["argus_term_1"] == "admin'--"
        assert vars_dict["argus_category_2"] == "users"
        assert vars_dict["argus_tag_3"] == "debug"

    def test_directive_bypass_wrapping(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } __type(name: \"Query\") { name } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.DIRECTIVE_BYPASS)
        directive_query = req["json"]["query"]

        assert "__schema @include(if: true)" in directive_query
        assert "types @skip(if: false)" in directive_query
        assert "__type @include(if: true)" in directive_query


# ============================================================================
# Suite 3: False Positive Rejection Against Hardened Endpoints
# ============================================================================

class TestAdversarialFalsePositiveRejection:
    """Stress tests false positive rejection across varied hardened, defensive, and edge-case server responses."""

    def test_rejection_of_standard_graphql_error_400_bad_request(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Realistic error response from Apollo Server / GraphQL-Java / Hasura
        error_bodies = [
            '{"errors": [{"message": "Cannot query field \\"__schema\\" on type \\"Query\\".", "locations": [{"line": 2, "column": 3}], "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}]}',
            '{"errors": [{"message": "Schema introspection is disabled in production environments.", "extensions": {"code": "FORBIDDEN"}}]}',
            '{"errors": [{"message": "GraphQL introspection is forbidden for unauthenticated callers."}]}',
            '{"errors": [{"message": "introspectionquery is not authorized."}]}',
        ]
        for body in error_bodies:
            resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
            assert analyzer.analyze_introspection(resp) is None

    def test_rejection_of_200_ok_with_null_data_and_errors(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"data": null, "errors": [{"message": "Cannot query field \\"__schema\\" on type \\"Query\\""}]}'
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        assert analyzer.analyze_introspection(resp) is None

    def test_rejection_of_waf_html_block_pages(self):
        analyzer = GraphQLSecurityAnalyzer()
        waf_pages = [
            (403, "<html><head><title>403 Forbidden - Cloudflare Ray ID: 89ab12</title></head><body><h1>Access Denied</h1><p>WAF Rule 100021 Triggered</p></body></html>"),
            (400, "<html><head><title>400 Bad Request - AWS WAF</title></head><body><h1>Request Blocked</h1></body></html>"),
            (406, "<html><body><h1>406 Not Acceptable - Akamai Edge</h1></body></html>"),
        ]
        for sc, html in waf_pages:
            resp = HttpResponse(success=False, status_code=sc, raw_body=html, body=html, url="https://target/graphql")
            assert analyzer.analyze_introspection(resp) is None
            assert analyzer.analyze_field_suggestions(resp) is None
            assert analyzer.analyze_query_depth(resp, depth=10) is None
            assert analyzer.analyze_batching_array(resp) is None
            assert analyzer.analyze_alias_multiplexing(resp, alias_count=20) is None

    def test_rejection_of_auth_denied_sensitive_fields_with_null(self):
        analyzer = GraphQLSecurityAnalyzer()
        for field_name in SENSITIVE_FIELD_NAMES:
            # 200 OK with null field data and permission error
            body = json.dumps({
                "data": {field_name: None},
                "errors": [{"message": f"You do not have permission to access field '{field_name}'"}],
            })
            resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
            assert analyzer.analyze_field_access_control(resp, sensitive_field=field_name) is None

            # 401 Unauthorized
            resp_401 = HttpResponse(success=False, status_code=401, raw_body='{"message": "Unauthorized"}', body='{"message": "Unauthorized"}', url="https://target/graphql")
            assert analyzer.analyze_field_access_control(resp_401, sensitive_field=field_name) is None

    def test_rejection_of_safe_sqli_and_cmdi_reflections(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Case A: SQL probe reflected safely in validation error without DB error
        safe_sql_body = '{"errors": [{"message": "Invalid user filter: 1\' OR \'1\'=\'1-- contains invalid characters"}]}'
        resp_sql = HttpResponse(success=False, status_code=400, raw_body=safe_sql_body, body=safe_sql_body, url="https://target/graphql")
        assert analyzer.analyze_injection(resp_sql, injection_type="sqli", payload="1' OR '1'='1--") is None

        # Case B: Command probe reflected in benign search string
        safe_cmd_body = '{"data": {"search": {"query": "; id ;", "count": 0, "results": []}}}'
        resp_cmd = HttpResponse(success=True, status_code=200, raw_body=safe_cmd_body, body=safe_cmd_body, url="https://target/graphql")
        assert analyzer.analyze_injection(resp_cmd, injection_type="cmdi", payload="; id ;") is None

    def test_rejection_of_hardened_query_depth_and_complexity(self):
        analyzer = GraphQLSecurityAnalyzer()
        defensive_depth_messages = [
            '{"errors": [{"message": "Query depth exceeds maximum allowed depth of 6"}]}',
            '{"errors": [{"message": "Max query depth exceeded. Current depth: 10, Maximum allowed: 5"}]}',
            '{"errors": [{"message": "Query is too complex. Complexity score 450 exceeds maximum allowable complexity 100"}]}',
        ]
        for msg in defensive_depth_messages:
            resp = HttpResponse(success=False, status_code=400, raw_body=msg, body=msg, url="https://target/graphql")
            assert analyzer.analyze_query_depth(resp, depth=10) is None
            assert analyzer.analyze_alias_multiplexing(resp, alias_count=20) is None


# ============================================================================
# Suite 4: Massive & Recursive Query Handling & Resource Safety
# ============================================================================

class TestAdversarialMassiveQueryAndResourceSafety:
    """Stress tests payload generation and analyzer execution against massive, deep, and recursive inputs."""

    def test_massive_depth_query_generation(self):
        gen = GraphQLPayloadGenerator()
        # Generate query of depth 100
        depth100 = gen.build_depth_query(depth=100, root_field="root", nested_field="child", leaf_field="val")
        assert "root {" in depth100
        assert depth100.count("child {") == 99
        assert "val" in depth100
        assert depth100.count("}") == 101  # 1 for query, 1 for root, 99 for children

    def test_massive_alias_multiplexing_query_generation(self):
        gen = GraphQLPayloadGenerator()
        # Generate 500 aliases
        alias500 = gen.build_alias_multiplexing_query(alias_count=500, field_name="__typename")
        assert "a1: __typename" in alias500
        assert "a500: __typename" in alias500
        assert len(alias500.split()) >= 1000

    def test_deeply_nested_json_depth_measurement_safety(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Build 60-level deeply nested dictionary structure
        curr: Dict[str, Any] = {"id": "leaf_node"}
        for i in range(60):
            curr = {f"nested_{i}": curr}
        nested_data = {"data": {"user": curr}}

        body = json.dumps(nested_data)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_query_depth(resp, depth=15, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.QUERY_DEPTH.value
        assert res.severity == GraphQLSeverity.HIGH.value

    def test_massive_schema_response_performance_and_stability(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Build a massive schema with 2,000 types and 20,000 fields
        types = [
            {
                "name": f"SchemaType_{i}",
                "kind": "OBJECT",
                "fields": [{"name": f"field_{j}", "type": {"name": "String", "kind": "SCALAR"}} for j in range(10)],
            }
            for i in range(2000)
        ]
        massive_schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": types,
                }
            }
        }
        body = json.dumps(massive_schema)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.severity == GraphQLSeverity.HIGH.value

    def test_candidate_endpoint_discovery_with_malformed_and_massive_uris(self):
        collector = GraphQLSecurityCollector()
        endpoints: List[Any] = [
            {"url": "not-a-valid-url"},
            {"url": "ftp://unsupported.proto/graphql"},
            {"url": "http://api.target.com/graphql"},
            {"url": "https://api.target.com/v1/graphql?auth=true#frag"},
            None,
            12345,
            "",
            "http://valid.domain/api/graphql",
        ]
        mission = Mission(
            target="target.com",
            endpoints=endpoints,
            live_hosts=["api.target.com", "http://internal.service:8080"],
        )
        candidates = collector._discover_candidate_endpoints(mission)
        assert len(candidates) >= 2
        cand_urls = [c["url"] for c in candidates]
        assert "http://api.target.com/graphql" in cand_urls
        assert "https://api.target.com/v1/graphql?auth=true#frag" in cand_urls


# ============================================================================
# Suite 5: End-to-End Adversarial Evasion Flow & Graph Integration
# ============================================================================

class TestAdversarialEndToEndEvasionScenarios:
    """End-to-end integration tests simulating evasive GraphQL targets that block naive probes."""

    def test_collector_evades_post_block_via_get_method_swapping(self):
        mock_client = AdversarialMockGraphQLHttpClient()
        # Endpoint returns 405 Method Not Allowed on POST, but exposes introspection on GET
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": f"T{i}", "kind": "OBJECT"} for i in range(8)],
                }
            }
        }
        mock_client.set_method_route("POST", "__schema", 405, '{"errors": [{"message": "POST not supported"}]}')
        mock_client.set_method_route("GET", "__schema", 200, json.dumps(schema_json))

        mission = Mission(
            target="http://get-only.graphql.local",
            endpoints=[{"url": "http://get-only.graphql.local/graphql", "method": "POST"}],
            evidence=EvidenceStore(),
            attack_surface_graph=KnowledgeGraph(),
        )
        collector = GraphQLSecurityCollector(http_client=mock_client)
        evidence_list = collector.collect(mission)

        # Introspection should be successfully detected via METHOD_SWAPPING
        assert len(evidence_list) >= 1
        intro_ev = next((e for e in evidence_list if e.metadata.get("technique") == "introspection"), None)
        assert intro_ev is not None
        assert intro_ev.metadata.get("mutation_strategy") == GraphQLMutationStrategy.METHOD_SWAPPING.value

    def test_collector_evades_json_filter_via_content_type_manipulation(self):
        mock_client = AdversarialMockGraphQLHttpClient()
        # Endpoint blocks application/json with 403 WAF rule, but accepts application/graphql
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": f"T{i}", "kind": "OBJECT"} for i in range(6)],
                }
            }
        }
        mock_client.set_header_route("Content-Type", "application/json", 403, '{"errors": [{"message": "WAF Block"}]}')
        mock_client.set_header_route("Content-Type", "application/graphql", 200, json.dumps(schema_json))

        mission = Mission(
            target="http://waf-graphql.local",
            endpoints=[{"url": "http://waf-graphql.local/graphql", "method": "POST"}],
            evidence=EvidenceStore(),
            attack_surface_graph=KnowledgeGraph(),
        )
        collector = GraphQLSecurityCollector(http_client=mock_client)
        evidence_list = collector.collect(mission)

        assert len(evidence_list) >= 1
        intro_ev = next((e for e in evidence_list if e.metadata.get("technique") == "introspection"), None)
        assert intro_ev is not None
        assert intro_ev.metadata.get("mutation_strategy") == GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION.value

    def test_collector_evades_keyword_block_via_alias_pollution(self):
        mock_client = AdversarialMockGraphQLHttpClient()
        # Endpoint blocks queries containing literal "__schema" without alias
        # but allows "_argus_schema: __schema"
        schema_json = {
            "data": {
                "_argus_schema": {
                    "_argus_qt": {"name": "Query"},
                    "_argus_types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(7)],
                }
            }
        }
        mock_client.set_route("_argus_schema", 200, json.dumps(schema_json))
        mock_client.set_route("__schema", 400, '{"errors": [{"message": "Querying __schema is prohibited"}]}')

        mission = Mission(
            target="http://alias-filtered.graphql.local",
            endpoints=[{"url": "http://alias-filtered.graphql.local/graphql", "method": "POST"}],
            evidence=EvidenceStore(),
            attack_surface_graph=KnowledgeGraph(),
        )
        collector = GraphQLSecurityCollector(http_client=mock_client)
        evidence_list = collector.collect(mission)

        assert len(evidence_list) >= 1
        intro_ev = next((e for e in evidence_list if e.metadata.get("technique") == "introspection"), None)
        assert intro_ev is not None
        assert intro_ev.metadata.get("mutation_strategy") == GraphQLMutationStrategy.ALIAS_POLLUTION.value

    def test_full_mission_graph_and_vulnerability_integrity(self):
        mock_client = AdversarialMockGraphQLHttpClient()
        # Mock responses for Introspection, Depth DoS, and BOPLA
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": f"T{i}", "kind": "OBJECT"} for i in range(10)],
                }
            }
        }
        mock_client.set_route("__schema", 200, json.dumps(schema_json))
        mock_client.set_route("DepthProbe5", 200, json.dumps({"data": {"user": {"friend": {"friend": {"friend": {"friend": {"id": "1"}}}}}}}))
        mock_client.set_route("AdminAuthProbe", 200, json.dumps({"data": {"admin": {"id": "1", "role": "SUPERADMIN"}}}))

        graph = KnowledgeGraph()
        mission = Mission(
            target="",
            endpoints=[{"url": "http://api.corp.local/graphql", "method": "POST"}],
            evidence=EvidenceStore(),
            attack_surface_graph=graph,
        )
        collector = GraphQLSecurityCollector(http_client=mock_client)
        evidence_list = collector.collect(mission)

        assert len(evidence_list) == 3
        techniques = {e.metadata.get("technique") for e in evidence_list}
        assert techniques == {"introspection", "query_depth", "field_access_control"}

        # Graph node and edge verification
        vuln_nodes = graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) == 3
        ep_nodes = graph.nodes_by_type("endpoint")
        assert len(ep_nodes) == 1
        lh_nodes = graph.nodes_by_type("live_host")
        assert len(lh_nodes) == 1

        # Check HAS_VULNERABILITY edges
        vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(vuln_edges) == 6  # 3 from live_host, 3 from endpoint


# ============================================================================
# Suite 6: Advanced Adversarial Boundary & Obfuscation Permutations
# ============================================================================

class TestAdversarialBoundaryAndObfuscations:
    """Stress tests complex edge cases in query mutations, comment stripping, and raw body recovery."""

    def test_raw_response_body_recovery_on_corrupted_json(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Corrupted JSON string that fails json.loads, but contains raw schema signatures and HTTP 200
        corrupted_body = '{"data": {"__schema": {"types": [{"name": "User", "kind": "OBJECT"}], "queryType": {"name": "Query"} -- CORRUPTED TAIL'
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=corrupted_body,
            body=corrupted_body,
            url="https://target/graphql",
        )
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.matched_signature == "raw_introspection_signature"

    def test_variable_extraction_unnamed_and_complex_queries(self):
        gen = GraphQLPayloadGenerator()
        # Unnamed query with string argument
        query = '{ user(id: "admin_user_001") { id email } }'
        req = gen.mutate_payload(query, GraphQLMutationStrategy.VARIABLE_EXTRACTION)
        assert "$argus_id_1: String" in req["json"]["query"]
        assert req["json"]["variables"]["argus_id_1"] == "admin_user_001"
        assert req["json"]["query"].startswith("query ($argus_id_1: String)")

    def test_field_suggestion_levenshtein_variations(self):
        analyzer = GraphQLSecurityAnalyzer()
        suggestion_samples = [
            '{"errors": [{"message": "Cannot query field \'passwrd\'. Did you mean \'password\'?"}]}',
            '{"errors": [{"message": "Field \'adm\' not found on type \'Query\'. Perhaps you meant \'admin\'?"}]}',
            '{"errors": [{"message": "Unknown field \'systm\'. suggestions: [\"system\", \"systemConfig\"]"}]}',
        ]
        for body in suggestion_samples:
            resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
            res = analyzer.analyze_field_suggestions(resp, endpoint_url="https://target/graphql")
            assert res is not None
            assert res.technique == GraphQLTechnique.FIELD_SUGGESTIONS.value
            assert res.severity == GraphQLSeverity.LOW.value

    def test_sql_injection_signatures_across_all_database_engines(self):
        analyzer = GraphQLSecurityAnalyzer()
        db_samples = [
            ("postgresql", '{"errors": [{"message": "PSQLException: ERROR: syntax error at or near \\"\'\\""}]}'),
            ("mysql", '{"errors": [{"message": "com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException: You have an error in your SQL syntax"}]}'),
            ("sqlite", '{"errors": [{"message": "SQLite3::SQLException: near \\"\'\\": syntax error"}]}'),
            ("oracle", '{"errors": [{"message": "java.sql.SQLException: ORA-01756: quoted string not properly terminated"}]}'),
            ("mssql", '{"errors": [{"message": "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark before the character string"}]}'),
            ("generic_sql", '{"errors": [{"message": "Database query failed: SQLSTATE[42000]: Syntax error or access violation"}]}'),
        ]
        for engine, body in db_samples:
            resp = HttpResponse(success=False, status_code=500, raw_body=body, body=body, url="https://target/graphql")
            res = analyzer.analyze_injection(resp, injection_type="sqli", payload="1' OR '1'='1", endpoint_url="https://target/graphql")
            assert res is not None
            assert res.technique == GraphQLTechnique.INJECTION_SQLI.value
            assert engine in res.matched_signature

    def test_command_injection_signatures_across_platforms(self):
        analyzer = GraphQLSecurityAnalyzer()
        cmd_samples = [
            ("passwd_entry", '{"data": {"system": "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"}}'),
            ("id_command", '{"data": {"ping": "uid=1000(argus) gid=1000(argus) groups=1000(argus)"}}'),
            ("windows_system", '{"data": {"exec": "Windows IP Configuration\\nEthernet adapter Local Area Connection:"}}'),
            ("command_error", '{"errors": [{"message": "/bin/sh: 1: foobar: not found"}]}'),
        ]
        for sig_key, body in cmd_samples:
            resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
            res = analyzer.analyze_injection(resp, injection_type="cmdi", payload="; id ;", endpoint_url="https://target/graphql")
            assert res is not None
            assert res.technique == GraphQLTechnique.INJECTION_CMDI.value
            assert res.severity == GraphQLSeverity.CRITICAL.value

    def test_fragment_recursion_dos_timeout_or_500(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Fast 200 OK -> Secure (None)
        fast_resp = HttpResponse(success=True, status_code=200, raw_body='{"data": null}', body='{"data": null}', url="https://target/graphql", elapsed=0.04)
        assert analyzer.analyze_fragment_recursion(fast_resp, elapsed=0.04) is None

        # Slow timeout (4.0s elapsed) -> Vulnerable
        slow_resp = HttpResponse(success=True, status_code=200, raw_body='{"data": null}', body='{"data": null}', url="https://target/graphql", elapsed=4.0)
        res_slow = analyzer.analyze_fragment_recursion(slow_resp, elapsed=4.0)
        assert res_slow is not None
        assert res_slow.technique == GraphQLTechnique.FRAGMENT_RECURSION.value
        assert res_slow.delay_delta == 4.0

        # Gateway timeout 504 -> Vulnerable
        timeout_resp = HttpResponse(success=False, status_code=504, raw_body="Gateway Timeout", body="Gateway Timeout", url="https://target/graphql", elapsed=1.5)
        res_timeout = analyzer.analyze_fragment_recursion(timeout_resp, elapsed=1.5)
        assert res_timeout is not None
        assert res_timeout.technique == GraphQLTechnique.FRAGMENT_RECURSION.value


# ============================================================================
# Suite 7: High-Throughput & Performance Stress Benchmarks
# ============================================================================

class TestAdversarialThroughputAndPerformance:
    """Empirical verification that analyzer evaluation is fast and non-blocking under heavy load."""

    def test_analyzer_throughput_under_heavy_load(self):
        import time
        analyzer = GraphQLSecurityAnalyzer()
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(25)],
                }
            }
        }
        body = json.dumps(schema_json)
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")

        start = time.perf_counter()
        iterations = 5000
        for _ in range(iterations):
            res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
            assert res is not None
        elapsed = time.perf_counter() - start

        # 5,000 analyzer executions must finish in under 1.5 seconds (< 0.3ms per analysis)
        assert elapsed < 1.5, f"Analyzer throughput exceeded SLA: {elapsed:.4f}s for {iterations} iterations"

