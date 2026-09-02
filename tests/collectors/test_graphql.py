"""
Comprehensive Unit and Integration Tests for GraphQLSecurityCollector, GraphQLPayloadGenerator,
GraphQLSecurityAnalyzer, AttackSurfaceGraph integration, TaskGenerator DAG wiring, and ToolRegistry.
"""
import json
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
    FIELD_SUGGESTION_SIGNATURES,
    DEPTH_LIMIT_DEFENSE_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    COMMAND_OUTPUT_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.reporting.cvss import CVSSCalculator
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockGraphQLHttpClient:
    """Mock HTTP client for GraphQL security testing supporting dynamic responses and route matching."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
        self.requested_gets: List[Dict[str, Any]] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.requested_gets.append({"url": target_url, "params": params, "headers": headers, "cookies": cookies})

        # Match parameters or URL substring
        query_val = params.get("query", "")
        for rk, (sc, b, el) in self.routes.items():
            if rk in target_url or rk in query_val or rk in str(params):
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body='{"data": {"__typename": "Query"}}', body='{"data": {"__typename": "Query"}}', url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": headers, "cookies": cookies})

        payload_str = ""
        if isinstance(data, (bytes, bytearray)):
            payload_str = data.decode("utf-8", errors="ignore")
        elif isinstance(data, str):
            payload_str = data
        elif json_data is not None:
            payload_str = json.dumps(json_data)

        # Match routes by substring in payload
        for rk, (sc, b, el) in self.routes.items():
            if rk in payload_str or rk in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Default clean baseline response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"data": {"__typename": "Query"}}',
            body='{"data": {"__typename": "Query"}}',
            url=target_url,
            elapsed=0.05,
        )


# ============================================================================
# Suite 1: Enums & Data Models
# ============================================================================

class TestGraphQLEnumsAndDataModels:
    def test_enums_integrity(self):
        assert GraphQLSeverity.CRITICAL == "critical"
        assert GraphQLSeverity.HIGH == "high"
        assert GraphQLSeverity.MEDIUM == "medium"
        assert GraphQLSeverity.LOW == "low"
        assert GraphQLSeverity.INFO == "info"

        assert GraphQLTechnique.INTROSPECTION == "introspection"
        assert GraphQLTechnique.TYPE_INTROSPECTION == "type_introspection"
        assert GraphQLTechnique.FIELD_SUGGESTIONS == "field_suggestions"
        assert GraphQLTechnique.QUERY_DEPTH == "query_depth"
        assert GraphQLTechnique.FRAGMENT_RECURSION == "fragment_recursion"
        assert GraphQLTechnique.BATCHING_ARRAY == "batching_array"
        assert GraphQLTechnique.BATCHING_ALIAS == "batching_alias"
        assert GraphQLTechnique.FIELD_ACCESS_CONTROL == "field_access_control"
        assert GraphQLTechnique.INJECTION_SQLI == "injection_sqli"
        assert GraphQLTechnique.INJECTION_CMDI == "injection_cmdi"

        assert GraphQLMutationStrategy.STANDARD == "standard"
        assert GraphQLMutationStrategy.METHOD_SWAPPING == "method_swapping"
        assert GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION == "content_type_manipulation"
        assert GraphQLMutationStrategy.QUERY_OBFUSCATION == "query_obfuscation"
        assert GraphQLMutationStrategy.ALIAS_POLLUTION == "alias_pollution"
        assert GraphQLMutationStrategy.VARIABLE_EXTRACTION == "variable_extraction"
        assert GraphQLMutationStrategy.DIRECTIVE_BYPASS == "directive_bypass"

    def test_security_result_dataclass(self):
        res = GraphQLSecurityResult(
            technique=GraphQLTechnique.INTROSPECTION.value,
            mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
            severity=GraphQLSeverity.HIGH.value,
            confidence=0.95,
            payload="query { __schema { types { name } } }",
            matched_signature="schema_introspection_types",
            evidence_snippet='{"types": [{"name": "User"}]}',
            endpoint_url="https://api.example.com/graphql",
        )
        assert res.technique == "introspection"
        assert res.vulnerability_type == "introspection"
        assert res.severity == "high"
        assert res.confidence == 0.95
        assert res.status_code == 200
        assert res.is_valid_finding is True
        assert res.template_id == "graphql-security"


# ============================================================================
# Suite 2: Payload Generator
# ============================================================================

class TestGraphQLPayloadGenerator:
    def test_baseline_and_introspection_generation(self):
        gen = GraphQLPayloadGenerator()
        baseline = gen.build_baseline_query()
        assert "__typename" in baseline

        full_intro = gen.build_introspection_query(full=True)
        assert "__schema" in full_intro
        assert "types" in full_intro
        assert "mutationType" in full_intro

        root_intro = gen.build_introspection_query(full=False)
        assert "__schema" in root_intro
        assert "types" not in root_intro

        type_intro = gen.build_type_introspection_query("Query")
        assert '__type(name: "Query")' in type_intro

    def test_depth_and_fragment_queries(self):
        gen = GraphQLPayloadGenerator()
        depth5 = gen.build_depth_query(depth=5, root_field="user", nested_field="friend", leaf_field="id")
        assert "user" in depth5
        assert depth5.count("friend") == 4
        assert "id" in depth5

        frag_cycle = gen.build_fragment_cycle_query()
        assert "...F1" in frag_cycle
        assert "fragment F1 on Query" in frag_cycle

        nested_frag = gen.build_nested_fragment_query()
        assert "fragment F1" in nested_frag
        assert "fragment F2" in nested_frag

    def test_batching_and_alias_queries(self):
        gen = GraphQLPayloadGenerator()
        batch_payload = gen.build_batch_array_payload(count=3)
        assert isinstance(batch_payload, list)
        assert len(batch_payload) == 3
        assert "query" in batch_payload[0]

        alias_query = gen.build_alias_multiplexing_query(alias_count=20)
        assert "a1: __typename" in alias_query
        assert "a20: __typename" in alias_query

    def test_field_auth_and_injection_probes(self):
        gen = GraphQLPayloadGenerator()
        auth_probes = gen.build_field_authorization_probes()
        assert len(auth_probes) >= 4
        fields = [p["field"] for p in auth_probes]
        assert "admin" in fields
        assert "users" in fields

        sqli_probes = gen.build_sqli_probes()
        assert len(sqli_probes) >= 3
        assert any("OR" in p["payload"] for p in sqli_probes)

        cmdi_probes = gen.build_cmdi_probes()
        assert len(cmdi_probes) >= 3
        assert any("whoami" in p["payload"] or "id" in p["payload"] for p in cmdi_probes)


# ============================================================================
# Suite 3: Mutation Strategies (All 6 Strategies)
# ============================================================================

class TestGraphQLMutationStrategies:
    def test_mutation_standard(self):
        gen = GraphQLPayloadGenerator()
        query = "query { user { id } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.STANDARD)
        assert req["method"] == "POST"
        assert req["headers"]["Content-Type"] == "application/json"
        assert req["json"]["query"] == query

    def test_mutation_method_swapping(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.METHOD_SWAPPING, variables={"limit": 10})
        assert req["method"] == "GET"
        assert req["params"]["query"] == query
        assert '"limit": 10' in req["params"]["variables"]
        assert req["json"] is None

    def test_mutation_content_type_manipulation(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION)
        assert req["method"] == "POST"
        assert req["headers"]["Content-Type"] == "application/graphql"
        assert req["data"] == query
        assert req["json"] is None

    def test_mutation_query_obfuscation(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.QUERY_OBFUSCATION)
        assert req["method"] == "POST"
        assert "# argus_guard" in req["json"]["query"]

    def test_mutation_alias_pollution(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.ALIAS_POLLUTION)
        assert "_argus_schema: __schema" in req["json"]["query"]
        assert "_argus_types: types" in req["json"]["query"]

    def test_mutation_variable_extraction(self):
        gen = GraphQLPayloadGenerator()
        query = 'query GetUser { user(id: "1\' OR \'1\'=\'1") { id } }'
        req = gen.mutate_payload(query, GraphQLMutationStrategy.VARIABLE_EXTRACTION)
        assert "$argus_id_1: String" in req["json"]["query"]
        assert req["json"]["variables"]["argus_id_1"] == "1' OR '1'='1"

    def test_mutation_directive_bypass(self):
        gen = GraphQLPayloadGenerator()
        query = "query { __schema { types { name } } }"
        req = gen.mutate_payload(query, GraphQLMutationStrategy.DIRECTIVE_BYPASS)
        assert "@include(if: true)" in req["json"]["query"]
        assert "@skip(if: false)" in req["json"]["query"]


# ============================================================================
# Suite 4: Security Analyzer Detection
# ============================================================================

class TestGraphQLSecurityAnalyzer:
    def test_introspection_full_schema_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(10)],
                }
            }
        }
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(schema_json), body=json.dumps(schema_json), url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INTROSPECTION.value
        assert res.severity == GraphQLSeverity.HIGH.value
        assert res.confidence == 0.95

    def test_type_introspection_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        type_json = {
            "data": {
                "__type": {
                    "name": "Query",
                    "fields": [{"name": "users"}, {"name": "admin"}],
                }
            }
        }
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(type_json), body=json.dumps(type_json), url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.TYPE_INTROSPECTION.value
        assert res.matched_signature == "type_introspection_fields"

    def test_field_suggestion_leakage(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "Cannot query field \\"usr\\" on type \\"Query\\". Did you mean \\"users\\" or \\"user\\"?"}]}'
        resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_field_suggestions(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.FIELD_SUGGESTIONS.value
        assert "Did you mean" in res.evidence_snippet

    def test_query_depth_dos_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        nested_data = {"data": {"user": {"friend": {"friend": {"friend": {"friend": {"id": "123"}}}}}}}
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(nested_data), body=json.dumps(nested_data), url="https://target/graphql")
        res = analyzer.analyze_query_depth(resp, depth=5, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.QUERY_DEPTH.value
        assert res.severity == GraphQLSeverity.MEDIUM.value

    def test_fragment_recursion_crash_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        resp_500 = HttpResponse(success=False, status_code=500, raw_body="Internal Server Error - Stack overflow", body="Internal Server Error - Stack overflow", url="https://target/graphql", elapsed=1.2)
        res = analyzer.analyze_fragment_recursion(resp_500, endpoint_url="https://target/graphql", elapsed=1.2)
        assert res is not None
        assert res.technique == GraphQLTechnique.FRAGMENT_RECURSION.value
        assert res.severity == GraphQLSeverity.HIGH.value

    def test_batching_array_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        batch_resp = [
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
        ]
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(batch_resp), body=json.dumps(batch_resp), url="https://target/graphql")
        res = analyzer.analyze_batching_array(resp, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.BATCHING_ARRAY.value

    def test_alias_multiplexing_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        alias_data = {"data": {f"a{i}": "Query" for i in range(1, 21)}}
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(alias_data), body=json.dumps(alias_data), url="https://target/graphql")
        res = analyzer.analyze_alias_multiplexing(resp, alias_count=20, endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.BATCHING_ALIAS.value

    def test_field_access_control_bopla_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        admin_data = {"data": {"admin": {"id": "1", "email": "admin@example.com", "role": "SUPERADMIN"}}}
        resp = HttpResponse(success=True, status_code=200, raw_body=json.dumps(admin_data), body=json.dumps(admin_data), url="https://target/graphql")
        res = analyzer.analyze_field_access_control(resp, sensitive_field="admin", endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.FIELD_ACCESS_CONTROL.value
        assert res.severity == GraphQLSeverity.HIGH.value

    def test_sqli_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        sqli_err = '{"errors": [{"message": "pg_query(): syntax error at or near \\"\'\\""}]}'
        resp = HttpResponse(success=False, status_code=500, raw_body=sqli_err, body=sqli_err, url="https://target/graphql")
        res = analyzer.analyze_injection(resp, injection_type="sqli", payload="1' OR '1'='1", endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INJECTION_SQLI.value
        assert "sqli_error_postgresql" in res.matched_signature

    def test_cmdi_detection(self):
        analyzer = GraphQLSecurityAnalyzer()
        cmd_out = '{"data": {"export": "uid=0(root) gid=0(root) groups=0(root)"}}'
        resp = HttpResponse(success=True, status_code=200, raw_body=cmd_out, body=cmd_out, url="https://target/graphql")
        res = analyzer.analyze_injection(resp, injection_type="cmdi", payload="; id ;", endpoint_url="https://target/graphql")
        assert res is not None
        assert res.technique == GraphQLTechnique.INJECTION_CMDI.value
        assert res.severity == GraphQLSeverity.CRITICAL.value


# ============================================================================
# Suite 5: False Positive Suppression & Hardened Server Handling
# ============================================================================

class TestGraphQLFalsePositiveSuppression:
    def test_hardened_introspection_disabled(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "GraphQL introspection is not allowed by administrator"}]}'
        resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, endpoint_url="https://target/graphql")
        assert res is None

    def test_hardened_depth_limit_enforced(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "Query depth of 15 exceeds maximum allowed depth 10"}]}'
        resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_query_depth(resp, depth=15, endpoint_url="https://target/graphql")
        assert res is None

    def test_hardened_fragment_cycle_rejected(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "Cannot spread fragment \\"F1\\" within itself."}]}'
        resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_fragment_recursion(resp, endpoint_url="https://target/graphql", elapsed=0.05)
        assert res is None

    def test_hardened_batching_disabled(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "Batch requests are not allowed"}]}'
        resp = HttpResponse(success=False, status_code=400, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_batching_array(resp, endpoint_url="https://target/graphql")
        assert res is None

    def test_unauthorized_field_null(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"data": {"admin": null}, "errors": [{"message": "Unauthorized access to field"}]}'
        resp = HttpResponse(success=False, status_code=403, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_field_access_control(resp, sensitive_field="admin", endpoint_url="https://target/graphql")
        assert res is None

    def test_echo_reflection_suppressed(self):
        analyzer = GraphQLSecurityAnalyzer()
        # Reflection of probe without database error
        body = '{"errors": [{"message": "Search query 1\' OR \'1\'=\'1 produced 0 items"}]}'
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_injection(resp, injection_type="sqli", payload="1' OR '1'=\'1", endpoint_url="https://target/graphql")
        assert res is None

    def test_baseline_subtraction_suppressed(self):
        analyzer = GraphQLSecurityAnalyzer()
        body = '{"errors": [{"message": "General Server Notice"}]}'
        resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        base_resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="https://target/graphql")
        res = analyzer.analyze_introspection(resp, baseline_response=base_resp, endpoint_url="https://target/graphql")
        assert res is None


# ============================================================================
# Suite 6: Collector Execution & Quadruple State Updates
# ============================================================================

class TestGraphQLCollectorExecution:
    def test_collector_empty_mission(self):
        mission = Mission(target="")
        collector = GraphQLSecurityCollector()
        evidence = collector.collect(mission)
        assert evidence == []

    def test_collector_candidate_discovery(self):
        collector = GraphQLSecurityCollector()
        mission = Mission(
            target="http://example.com",
            endpoints=[{"url": "http://example.com/api/graphql", "method": "POST"}],
            live_hosts=["http://example.com"],
        )
        candidates = collector._discover_candidate_endpoints(mission)
        urls = [c["url"] for c in candidates]
        assert "http://example.com/api/graphql" in urls

    def test_collector_full_collection_and_quadruple_state_update(self):
        mock_client = MockGraphQLHttpClient()
        # Set up mock vulnerable responses for Introspection and Batching
        schema_json = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(8)],
                }
            }
        }
        mock_client.set_route("__schema", 200, json.dumps(schema_json))
        mock_client.set_route("BatchOp", 200, json.dumps([{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]))

        graph = KnowledgeGraph()
        mission = Mission(
            target="http://api.target.local",
            endpoints=[{"url": "http://api.target.local/graphql", "method": "POST"}],
            live_hosts=["http://api.target.local"],
            evidence=EvidenceStore(),
            attack_surface_graph=graph,
        )
        controlled = ControlledMission(mission)
        collector = GraphQLSecurityCollector(http_client=mock_client)

        evidence_items = collector.collect(controlled)
        assert len(evidence_items) >= 1

        # Check raw mission evidence
        assert len(mission.evidence) >= 1
        ev = evidence_items[0]
        assert ev.category == "graphql_security"
        assert ev.status == "CONFIRMED"

        # Check mission vulnerabilities list
        assert len(mission.vulnerabilities) >= 1
        assert any("GraphQL" in v.get("name", "") for v in mission.vulnerabilities)

        # Check AttackSurfaceGraph nodes and edges
        assert len(graph.nodes) >= 2
        vuln_nodes = graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) >= 1
        ep_nodes = graph.nodes_by_type("endpoint")
        assert len(ep_nodes) >= 1

        # Check HAS_VULNERABILITY and HAS_ENDPOINT edges
        vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(vuln_edges) >= 1

    def test_collector_hardened_server_zero_evidence(self):
        mock_client = MockGraphQLHttpClient()
        mock_client.set_route("__schema", 400, '{"errors": [{"message": "GraphQL introspection is not allowed"}]}')
        mock_client.set_route("DepthProbe", 400, '{"errors": [{"message": "Query depth of 15 exceeds maximum depth 10"}]}')
        mock_client.set_route("BatchOp", 400, '{"errors": [{"message": "Batch queries not supported"}]}')

        mission = Mission(
            target="http://hardened.target.local",
            endpoints=[{"url": "http://hardened.target.local/graphql", "method": "POST"}],
            live_hosts=["http://hardened.target.local"],
            evidence=EvidenceStore(),
        )
        collector = GraphQLSecurityCollector(http_client=mock_client)
        evidence = collector.collect(mission)
        assert len(evidence) == 0
        assert len(mission.evidence) == 0

    def test_collector_execute_alias(self):
        mock_client = MockGraphQLHttpClient()
        collector = GraphQLCollector(http_client=mock_client)
        mission = Mission(target="http://example.com")
        res = collector.execute(mission)
        assert isinstance(res, list)


# ============================================================================
# Suite 7: Pipeline, DAG, Registry & Graph Integration
# ============================================================================

class TestGraphQLPipelineAndGraphIntegration:
    def test_registry_tool_and_aliases(self):
        tool = registry.get("graphql_security")
        assert tool is not None
        assert tool.id == "graphql_security"
        assert tool.priority == 95
        assert "graphql_security_detector" in tool.capabilities

        # Test all aliases
        for alias in (
            "graphql_security_collector",
            "graphql_detector",
            "graphql_vuln",
            "graphql_vulnerability",
            "graphql_introspection",
            "graphql_collector",
            "graphql_security_validator",
            "graphql_dos",
            "graphql_batching",
        ):
            alias_tool = registry.get(alias)
            assert alias_tool is not None
            assert alias_tool.id == "graphql_security"

    def test_plugin_executor_fallback(self):
        adapter = PluginExecutorAdapter()
        instance = adapter._instantiate_specialist_fallback("graphql_security")
        assert isinstance(instance, GraphQLSecurityCollector)

        alias_instance = adapter._instantiate_specialist_fallback("graphql_vuln")
        assert isinstance(alias_instance, GraphQLSecurityCollector)

        collector_instance = adapter._instantiate_specialist_fallback("graphql_collector")
        assert isinstance(collector_instance, GraphQLSecurityCollector)

    def test_task_generator_dag_wiring(self):
        # 1. Template validation
        template = _RECON_TEMPLATES["graphql_security"]
        assert template["dependencies"] == ["Discover API Endpoints"]
        assert template["required_inputs"] == ["endpoints"]
        assert template["metadata"]["tool_id"] == "graphql_security"

        # 2. Gap resolution
        mission = Mission(target="example.com", endpoints=["http://example.com/graphql"])
        tg = TaskGenerator(mission)
        gap = CoverageGap(
            category=TaskCategory.EVIDENCE_CORRELATION,
            description="GraphQL introspection and query depth validation required",
            area="graphql security",
        )
        resolved_template = tg._resolve_template_for_gap(gap)
        assert resolved_template["metadata"]["tool_id"] == "graphql_security"

        tasks = tg.from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].title == "Validate GraphQL Security"
        assert tasks[0].dependencies == ["Discover API Endpoints"]
        assert "http://example.com/graphql" in tasks[0].required_inputs

    def test_attack_surface_graph_builder(self):
        graph = KnowledgeGraph()
        builder = AttackSurfaceGraphBuilder()
        evidence_items = [
            Evidence(
                category="graphql_security",
                title="GraphQL Schema Introspection Enabled: https://api.example.com/graphql",
                description="Schema introspection enabled",
                value="https://api.example.com/graphql",
                severity="high",
                metadata={
                    "url": "https://api.example.com/graphql",
                    "host": "https://api.example.com",
                    "technique": "introspection",
                    "template_id": "graphql-introspection",
                },
            )
        ]

        populated_graph = builder.build_from_evidence(evidence_items, target="api.example.com", graph=graph)
        assert len(populated_graph.nodes) >= 3  # live_host, endpoint, vulnerability
        vuln_nodes = populated_graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) == 1
        assert vuln_nodes[0].metadata.get("severity") == "high"

        # Verify HAS_VULNERABILITY edges
        has_vuln_edges = [e for e in populated_graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(has_vuln_edges) >= 2  # live_host -> vuln, endpoint -> vuln

    def test_cvss_and_cwe_resolution(self):
        assert "graphql_security" in CVSSCalculator.CWE_DATABASE
        assert CVSSCalculator.CWE_DATABASE["graphql_security"].id == "CWE-200"

        assert "graphql_dos" in CVSSCalculator.CWE_DATABASE
        assert CVSSCalculator.CWE_DATABASE["graphql_dos"].id == "CWE-400"

        assert "graphql_batching" in CVSSCalculator.CWE_DATABASE
        assert CVSSCalculator.CWE_DATABASE["graphql_batching"].id == "CWE-799"

        assert "graphql_access_control" in CVSSCalculator.CWE_DATABASE
        assert CVSSCalculator.CWE_DATABASE["graphql_access_control"].id == "CWE-285"
