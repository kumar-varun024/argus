"""
GraphQL Security Detection Collector for ARGUS.

Actively validates discovered GraphQL endpoints for security misconfigurations,
access control bypasses, query complexity vulnerabilities, and injection vectors:
1. Introspection & Schema Leakage:
   - Full schema introspection (__schema, types, fields, args)
   - Type-specific introspection (__type(name: "Query"))
   - Field suggestion leakage (Did you mean ...? / Levenshtein matching)
2. Query Depth & Complexity DoS:
   - Unbounded recursive nested query probing (depth 5, 10, 15)
   - Circular fragment expansion and nested fragment amplification
3. Batching & Query Multiplexing Abuse:
   - HTTP query array batching ([{query: ...}, {query: ...}])
   - Alias multiplexing abuse (20+ aliases in a single query)
4. Field-Level Access Control (BOPLA) & Injection:
   - Privileged/sensitive field discovery (admin, users, passwordHash, debug, token)
   - GraphQL argument SQL injection (SQLi error reflection & delay)
   - GraphQL argument Command injection (OS command reflection & error)

Supports 6 distinct payload mutation & bypass strategies:
1. METHOD_SWAPPING: POST <-> GET (?query=...) <-> POST urlencoded
2. CONTENT_TYPE_MANIPULATION: application/graphql, text/plain, application/json, form-urlencoded
3. QUERY_OBFUSCATION: Inline comments (# ...\\n), comma whitespace, newline splits
4. ALIAS_POLLUTION: Custom alias identifiers (_argus_schema: __schema)
5. VARIABLE_EXTRACTION: Extracting literals into operation $variables
6. DIRECTIVE_BYPASS: Wrapping fields in @include(if: true) / @skip(if: false)

Emits structured Evidence(category="graphql_security"), updates mission vulnerabilities,
ControlledMission findings, and expands AttackSurfaceGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


class GraphQLSeverity(str, Enum):
    """GraphQL vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Backwards compatibility alias
Severity = GraphQLSeverity


class GraphQLTechnique(str, Enum):
    """Enumeration of GraphQL security detection techniques."""
    INTROSPECTION = "introspection"
    TYPE_INTROSPECTION = "type_introspection"
    FIELD_SUGGESTIONS = "field_suggestions"
    QUERY_DEPTH = "query_depth"
    FRAGMENT_RECURSION = "fragment_recursion"
    BATCHING_ARRAY = "batching_array"
    BATCHING_ALIAS = "batching_alias"
    FIELD_ACCESS_CONTROL = "field_access_control"
    INJECTION_SQLI = "injection_sqli"
    INJECTION_CMDI = "injection_cmdi"


class GraphQLMutationStrategy(str, Enum):
    """Enumeration of GraphQL query mutation and bypass strategies."""
    STANDARD = "standard"
    METHOD_SWAPPING = "method_swapping"
    CONTENT_TYPE_MANIPULATION = "content_type_manipulation"
    QUERY_OBFUSCATION = "query_obfuscation"
    ALIAS_POLLUTION = "alias_pollution"
    VARIABLE_EXTRACTION = "variable_extraction"
    DIRECTIVE_BYPASS = "directive_bypass"


@dataclass
class GraphQLSecurityResult:
    """Represents the parsed outcome of a GraphQL security validation probe."""
    technique: str
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    parameter: Optional[str] = None
    parameter_type: str = "graphql_query"
    status_code: int = 200
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "graphql-security"
    vulnerability_type: Optional[str] = None

    def __post_init__(self):
        if not self.vulnerability_type:
            self.vulnerability_type = self.technique


# Signature Catalogs & Heuristics
INTROSPECTION_SIGNATURES: Dict[str, re.Pattern] = {
    "types_list": re.compile(r'["\']types["\']\s*:\s*\[', re.IGNORECASE),
    "schema_root": re.compile(r'["\']__schema["\']\s*:\s*\{', re.IGNORECASE),
    "query_type": re.compile(r'["\']queryType["\']\s*:\s*\{', re.IGNORECASE),
    "mutation_type": re.compile(r'["\']mutationType["\']\s*:\s*\{', re.IGNORECASE),
    "type_info": re.compile(r'["\']__type["\']\s*:\s*\{', re.IGNORECASE),
}

HARDENED_INTROSPECTION_SIGNATURES: Dict[str, re.Pattern] = {
    "introspection_disabled": re.compile(
        r"(?:introspection\s+(?:is\s+)?(?:disabled|not\s+(?:allowed|permitted|enabled))|cannot\s+query\s+field\s+['\"]__schema['\"]|introspectionquery.*not\s+authorized|schema\s+introspection\s+is\s+disabled)",
        re.IGNORECASE,
    ),
    "introspection_forbidden": re.compile(
        r"(?:graphql\s+introspection\s+is\s+forbidden|introspection\s+queries\s+are\s+not\s+allowed)",
        re.IGNORECASE,
    ),
}

FIELD_SUGGESTION_SIGNATURES: Dict[str, re.Pattern] = {
    "did_you_mean": re.compile(
        r'(?:did\s+you\s+mean\s+\\?["\'](?P<suggestion>[^"\'\\]+)\\?["\']|\bperhaps\s+you\s+meant\b|\bsuggestions?:\s*\[|\bdid\s+you\s+mean\b)',
        re.IGNORECASE,
    ),
}

DEPTH_LIMIT_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "max_depth_exceeded": re.compile(
        r"(?:max(?:imum)?\s+(?:query\s+)?depth\s+(?:of\s+\d+\s+)?exceeded|query\s+depth\s+exceeds|exceeds\s+maximum\s+(?:allowed\s+)?depth|complexity\s+(?:score\s+)?exceeded|query\s+(?:is\s+)?too\s+complex)",
        re.IGNORECASE,
    ),
}

FRAGMENT_CYCLE_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "cannot_spread_fragment": re.compile(
        r"(?:cannot\s+spread\s+fragment|fragment\s+cycle|circular\s+fragment|recursive\s+fragment|infinite\s+loop\s+in\s+fragment|spread.*within\s+itself)",
        re.IGNORECASE,
    ),
}

BATCH_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "batch_disabled": re.compile(
        r"(?:batch(?:ing)?\s+(?:is\s+)?(?:not\s+supported|disabled|forbidden)|batch\s+requests?\s+(?:are\s+)?not\s+allowed|operation\s+array\s+not\s+supported)",
        re.IGNORECASE,
    ),
}

SQL_ERROR_SIGNATURES: Dict[str, re.Pattern] = {
    "postgresql": re.compile(
        r"(?:syntax error at or near|pg_query\(\)|org\.postgresql\.util\.PSQLException|PostgreSQL query failed)",
        re.IGNORECASE,
    ),
    "mysql": re.compile(
        r"(?:You have an error in your SQL syntax|mysql_fetch|com\.mysql\.jdbc|MySQLSyntaxErrorException)",
        re.IGNORECASE,
    ),
    "sqlite": re.compile(
        r"(?:SQLite3::SQLException|near\s+['\"][^'\"]+['\"]: syntax error|sqlite_error|SQLITE_ERROR)",
        re.IGNORECASE,
    ),
    "oracle": re.compile(
        r"(?:ORA-01756|ORA-00933|ORA-00907|Oracle error)",
        re.IGNORECASE,
    ),
    "mssql": re.compile(
        r"(?:Unclosed quotation mark before the character string|Microsoft OLE DB Provider for SQL Server|com\.microsoft\.sqlserver\.jdbc)",
        re.IGNORECASE,
    ),
    "generic_sql": re.compile(
        r"(?:SQL syntax.*error|SQLSTATE\[[0-9A-Z]+\]|unterminated quoted string|quoted string not properly terminated)",
        re.IGNORECASE,
    ),
}

COMMAND_OUTPUT_SIGNATURES: Dict[str, re.Pattern] = {
    "passwd_entry": re.compile(
        r"(?:root:.*?:0:0:|daemon:.*?:1:1:|[a-zA-Z0-9_\-]+:[^:\n]+:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*)",
        re.IGNORECASE,
    ),
    "id_command": re.compile(
        r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+\([a-zA-Z0-9_\-]+\)",
        re.IGNORECASE,
    ),
    "windows_system": re.compile(
        r"(?:Windows IP Configuration|Directory of [A-Z]:\\|Volume in drive [A-Z] is)",
        re.IGNORECASE,
    ),
    "command_error": re.compile(
        r"(?:/bin/sh:\s*\d*:\s*.*not found|bash:\s*.*command not found|sh:\s*.*not found|Cannot run program)",
        re.IGNORECASE,
    ),
}

SENSITIVE_FIELD_NAMES: List[str] = [
    "admin",
    "system",
    "debug",
    "users",
    "passwordHash",
    "password",
    "token",
    "secret",
    "apiKey",
    "databaseUrl",
    "privateKey",
    "systemConfig",
    "credentials",
]


class GraphQLPayloadGenerator:
    """Generates GraphQL probes across all vulnerability vectors and mutation strategies."""

    @staticmethod
    def build_baseline_query() -> str:
        """Builds a minimal benign query for baseline profiling."""
        return "query ArgusBaseline { __typename }"

    @staticmethod
    def build_introspection_query(full: bool = True) -> str:
        """Builds full schema introspection query."""
        if full:
            return """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { name kind }
        }
      }
    }
  }
}"""
        return """query RootIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
  }
}"""

    @staticmethod
    def build_type_introspection_query(type_name: str = "Query") -> str:
        """Builds targeted single-type introspection query."""
        return f"""query TypeIntrospection {{
  __type(name: "{type_name}") {{
    name
    kind
    fields {{
      name
      type {{ name kind }}
    }}
  }}
}}"""

    @staticmethod
    def build_suggestion_probes() -> List[Dict[str, Any]]:
        """Builds misspelled field queries designed to trigger suggestion leakage."""
        return [
            {"name": "usr", "query": "query SuggestionProbeUsr { usr { id } }"},
            {"name": "passwrd", "query": "query SuggestionProbePass { passwrd }"},
            {"name": "adm", "query": "query SuggestionProbeAdm { adm { id } }"},
            {"name": "systm", "query": "query SuggestionProbeSystm { systm { info } }"},
            {"name": "accnt", "query": "query SuggestionProbeAccnt { accnt { id } }"},
            {"name": "tkn", "query": "query SuggestionProbeTkn { tkn }"},
        ]

    @staticmethod
    def build_depth_query(
        depth: int = 5,
        root_field: str = "user",
        nested_field: str = "friend",
        leaf_field: str = "id",
    ) -> str:
        """Builds dynamically nested recursive query of arbitrary depth."""
        inner = leaf_field
        for _ in range(max(1, depth - 1)):
            inner = f"{nested_field} {{ {inner} }}"
        return f"query DepthProbe{depth} {{ {root_field} {{ {inner} }} }}"

    @staticmethod
    def build_fragment_cycle_query() -> str:
        """Builds circular fragment reference query."""
        return "query FragmentCycleProbe { ...F1 } fragment F1 on Query { ...F1 }"

    @staticmethod
    def build_nested_fragment_query() -> str:
        """Builds nested circular fragment chain query."""
        return """query NestedFragmentCycle {
  ...F1
}
fragment F1 on Query {
  ...F2
}
fragment F2 on Query {
  ...F1
}"""

    @staticmethod
    def build_batch_array_payload(
        queries: Optional[List[str]] = None,
        count: int = 3,
    ) -> List[Dict[str, Any]]:
        """Builds a JSON array batch containing multiple query operations."""
        if not queries:
            queries = [f"query BatchOp{i} {{ __typename }}" for i in range(count)]
        return [{"query": q} for q in queries]

    @staticmethod
    def build_alias_multiplexing_query(
        alias_count: int = 20,
        field_name: str = "__typename",
    ) -> str:
        """Builds an alias multiplexing query containing N aliased fields."""
        aliases = " ".join([f"a{i}: {field_name}" for i in range(1, alias_count + 1)])
        return f"query AliasMultiplexingProbe {{ {aliases} }}"

    @staticmethod
    def build_field_authorization_probes() -> List[Dict[str, Any]]:
        """Builds probes for privileged/administrative fields."""
        return [
            {
                "field": "admin",
                "query": "query AdminAuthProbe { admin { id username email role permissions } }",
            },
            {
                "field": "users",
                "query": "query UsersAuthProbe { users { id username email passwordHash token } }",
            },
            {
                "field": "debug",
                "query": "query DebugAuthProbe { debug { systemInfo environment config secrets } }",
            },
            {
                "field": "tokens",
                "query": "query TokenAuthProbe { tokens { id secret token key } }",
            },
            {
                "field": "systemConfig",
                "query": "query ConfigAuthProbe { systemConfig { databaseUrl apiKey secretKey } }",
            },
        ]

    @staticmethod
    def build_sqli_probes() -> List[Dict[str, Any]]:
        """Builds SQL injection probes via GraphQL arguments."""
        return [
            {
                "name": "sqli_or",
                "query": 'query SQLiProbeOr { user(id: "1\' OR \'1\'=\'1--") { id username } }',
                "payload": "1' OR '1'='1--",
            },
            {
                "name": "sqli_union",
                "query": 'query SQLiProbeUnion { search(query: "1\' UNION SELECT null, null, null--") { results } }',
                "payload": "1' UNION SELECT null, null, null--",
            },
            {
                "name": "sqli_comment",
                "query": 'query SQLiProbeComment { node(id: "1\' OR 1=1 #") { id } }',
                "payload": "1' OR 1=1 #",
            },
        ]

    @staticmethod
    def build_cmdi_probes() -> List[Dict[str, Any]]:
        """Builds OS command injection probes via GraphQL arguments."""
        return [
            {
                "name": "cmdi_id",
                "query": 'query CmdIProbeId { system(cmd: "; id ;") { output } }',
                "payload": "; id ;",
            },
            {
                "name": "cmdi_whoami",
                "query": 'query CmdIProbeWhoami { export(format: "pdf; whoami") { result } }',
                "payload": "pdf; whoami",
            },
            {
                "name": "cmdi_cat_passwd",
                "query": 'query CmdIProbePasswd { ping(host: "127.0.0.1 | cat /etc/passwd") { status } }',
                "payload": "127.0.0.1 | cat /etc/passwd",
            },
        ]

    @classmethod
    def mutate_payload(
        cls,
        query: str,
        strategy: Union[GraphQLMutationStrategy, str],
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Applies a mutation/bypass strategy to a GraphQL query.

        Returns a structured dictionary specifying HTTP method, headers, params,
        JSON body, raw body data, and metadata.
        """
        strat = (
            strategy.value
            if isinstance(strategy, GraphQLMutationStrategy)
            else str(strategy).lower()
        )

        # Base request configuration
        req: Dict[str, Any] = {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "params": None,
            "json": {
                "query": query,
                "variables": variables or {},
            },
            "data": None,
            "strategy": strat,
            "query": query,
            "variables": variables or {},
        }
        if operation_name:
            req["json"]["operationName"] = operation_name

        if strat == GraphQLMutationStrategy.STANDARD.value:
            return req

        elif strat == GraphQLMutationStrategy.METHOD_SWAPPING.value:
            # Convert to GET with query string parameter
            params: Dict[str, Any] = {"query": query}
            if variables:
                params["variables"] = json.dumps(variables)
            if operation_name:
                params["operationName"] = operation_name
            req["method"] = "GET"
            req["params"] = params
            req["json"] = None
            req["headers"] = {}
            return req

        elif strat == GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION.value:
            # Send raw query string with application/graphql header
            req["method"] = "POST"
            req["headers"] = {"Content-Type": "application/graphql"}
            req["json"] = None
            req["data"] = query
            return req

        elif strat == GraphQLMutationStrategy.QUERY_OBFUSCATION.value:
            # Obfuscate query by injecting comments, commas, and newlines
            obfuscated = re.sub(r"[ \t]+", ", ", query)
            obfuscated = obfuscated.replace("{", "# argus_guard\n{\n")
            obfuscated = obfuscated.replace("}", "\n# argus_end\n}")
            req["json"]["query"] = obfuscated
            req["query"] = obfuscated
            return req

        elif strat == GraphQLMutationStrategy.ALIAS_POLLUTION.value:
            # Inject alias renaming on introspection keywords
            polluted = query
            polluted = re.sub(r"\b__schema\b", "_argus_schema: __schema", polluted)
            polluted = re.sub(r"\btypes\b", "_argus_types: types", polluted)
            polluted = re.sub(r"\bqueryType\b", "_argus_qt: queryType", polluted)
            polluted = re.sub(r"\bmutationType\b", "_argus_mt: mutationType", polluted)
            polluted = re.sub(r"\b__type\b", "_argus_type: __type", polluted)
            req["json"]["query"] = polluted
            req["query"] = polluted
            return req

        elif strat == GraphQLMutationStrategy.VARIABLE_EXTRACTION.value:
            # Extract literal arguments into operation variables
            extracted_query = query
            extracted_vars = dict(variables or {})
            # Look for double-quoted strings inside arguments
            matches = list(re.finditer(r'([a-zA-Z0-9_]+)\s*:\s*"([^"]+)"', query))
            if matches:
                var_defs = []
                for i, m in enumerate(matches, 1):
                    arg_name = m.group(1)
                    val = m.group(2)
                    var_name = f"argus_{arg_name}_{i}"
                    extracted_vars[var_name] = val
                    var_defs.append(f"${var_name}: String")
                    extracted_query = extracted_query.replace(
                        m.group(0), f"{arg_name}: ${var_name}", 1
                    )
                # Prefix query with variable definitions if not already declared
                if "query " in extracted_query:
                    extracted_query = re.sub(
                        r"query\s*([a-zA-Z0-9_]*)\s*\{",
                        f"query \\1({', '.join(var_defs)}) {{",
                        extracted_query,
                        count=1,
                    )
                else:
                    extracted_query = f"query ({', '.join(var_defs)}) {extracted_query}"
            req["json"]["query"] = extracted_query
            req["json"]["variables"] = extracted_vars
            req["query"] = extracted_query
            req["variables"] = extracted_vars
            return req

        elif strat == GraphQLMutationStrategy.DIRECTIVE_BYPASS.value:
            # Wrap schema fields in @include(if: true) / @skip(if: false)
            directive_query = query
            directive_query = re.sub(
                r"\b__schema\b", "__schema @include(if: true)", directive_query
            )
            directive_query = re.sub(
                r"\btypes\b", "types @skip(if: false)", directive_query
            )
            directive_query = re.sub(
                r"\b__type\b", "__type @include(if: true)", directive_query
            )
            req["json"]["query"] = directive_query
            req["query"] = directive_query
            return req

        return req


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


class GraphQLSecurityCollector(BaseCollector):
    """
    Active GraphQL Security Detection Collector for ARGUS.

    Identifies GraphQL endpoints and actively fuzzes for introspection exposure,
    field suggestion leakage, query complexity DoS, batch multiplexing abuse,
    and field authorization / injection flaws across 6 mutation strategies.
    """

    DEFAULT_GRAPHQL_PATHS: List[str] = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/api/query",
        "/gql",
        "/graphql/console",
        "/graphiql",
        "/playground",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
    ) -> None:
        self.http_client = http_client
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint
        self.payload_generator = GraphQLPayloadGenerator()
        self.analyzer = GraphQLSecurityAnalyzer()

    def _execute_request(
        self,
        mission: Any,
        method: str = "POST",
        url: str = "",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Polymorphic HTTP request execution supporting mock clients and AuthenticatedHttpClient."""
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.http_client is not None:
                client = self.http_client

                # 1. Direct method calls: client.get(...), client.post(...)
                if method == "GET" and hasattr(client, "get"):
                    try:
                        return client.get(
                            mission,
                            url,
                            params=params,
                            headers=req_headers,
                            cookies=req_cookies,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        return client.get(
                            url,
                            params=params,
                            headers=req_headers,
                            cookies=req_cookies,
                        )
                if method == "POST" and hasattr(client, "post"):
                    kwargs: Dict[str, Any] = {
                        "headers": req_headers,
                        "cookies": req_cookies,
                    }
                    if params:
                        kwargs["params"] = params
                    if json_data is not None:
                        kwargs["json"] = json_data
                    if data is not None:
                        kwargs["data"] = data
                    try:
                        return client.post(
                            mission, url, timeout=self.timeout, **kwargs
                        )
                    except TypeError:
                        return client.post(url, **kwargs)

                # 2. Universal client.request(...)
                if hasattr(client, "request"):
                    try:
                        return client.request(
                            mission,
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        return client.request(
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                        )

                # 3. Callable mock
                if callable(client):
                    return client(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                    )

            # Fallback to production AuthenticatedHttpClient
            with AuthenticatedHttpClient(
                timeout=self.timeout, max_retries=1
            ) as client:
                if method == "GET":
                    return client.get(
                        mission,
                        url,
                        params=params,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
                elif method == "POST":
                    return client.post(
                        mission,
                        url,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
                else:
                    return client.request(
                        mission,
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
        except Exception as e:
            logger.debug(f"GraphQLSecurityCollector: Request to {url} failed: {e}")
        return None

    def _discover_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """Extracts candidate GraphQL endpoints from mission assets and default path probes."""
        raw_mission = getattr(mission, "_mission", mission)
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        target = str(getattr(raw_mission, "target", "") or "")

        # 1. Process explicitly discovered endpoints
        for ep in endpoints:
            if isinstance(ep, dict):
                u = ep.get("url") or ""
                m = ep.get("method") or "POST"
                headers = ep.get("headers") or {}
                cookies = ep.get("cookies") or {}
            else:
                u = str(ep)
                m = "POST"
                headers = {}
                cookies = {}

            if not u or not u.startswith("http"):
                continue

            parsed = urllib.parse.urlparse(u)
            path_lower = parsed.path.lower()
            if any(gp in path_lower for gp in ("/graphql", "/query", "/gql")):
                if u not in seen_urls:
                    seen_urls.add(u)
                    candidates.append({"url": u, "method": m, "headers": headers, "cookies": cookies})

        # 2. Synthesize candidate endpoints from live hosts or target if no explicit GraphQL endpoints
        host_urls: List[str] = []
        for lh in live_hosts:
            u = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
            if u and u.startswith("http"):
                host_urls.append(u.rstrip("/"))
            elif u:
                host_urls.append(f"http://{u}".rstrip("/"))

        if not host_urls and target:
            t_url = target if target.startswith("http") else f"http://{target}"
            host_urls.append(t_url.rstrip("/"))

        for base in host_urls:
            for path in self.DEFAULT_GRAPHQL_PATHS:
                full_url = f"{base}{path}"
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    candidates.append({"url": full_url, "method": "POST", "headers": {}, "cookies": {}})

        # If still empty but general endpoints exist, test those endpoints as candidates
        if not candidates and endpoints:
            for ep in endpoints:
                u = ep.get("url") if isinstance(ep, dict) else str(ep)
                if u and u.startswith("http") and u not in seen_urls:
                    seen_urls.add(u)
                    candidates.append({"url": u, "method": "POST", "headers": {}, "cookies": {}})

        return candidates

    def _dispatch_mutation(
        self,
        mission: Any,
        target_url: str,
        query: str,
        strategy: GraphQLMutationStrategy,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
        base_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Dispatches an HTTP request with the specified mutation strategy."""
        req_spec = self.payload_generator.mutate_payload(
            query=query,
            strategy=strategy,
            variables=variables,
            operation_name=operation_name,
        )

        headers = dict(base_headers or {})
        headers.update(req_spec.get("headers") or {})

        return self._execute_request(
            mission=mission,
            method=req_spec["method"],
            url=target_url,
            params=req_spec.get("params"),
            data=req_spec.get("data"),
            json_data=req_spec.get("json"),
            headers=headers,
            cookies=cookies,
        )

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        result: GraphQLSecurityResult,
    ) -> Evidence:
        """Executes quadruple state update across mission evidence, vulnerabilities, graph, and wrapper."""
        raw_mission = getattr(mission, "_mission", mission)
        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_titles = {
            GraphQLTechnique.INTROSPECTION.value: "GraphQL Schema Introspection Enabled",
            GraphQLTechnique.TYPE_INTROSPECTION.value: "GraphQL Type Introspection Exposed",
            GraphQLTechnique.FIELD_SUGGESTIONS.value: "GraphQL Field Suggestion Leakage",
            GraphQLTechnique.QUERY_DEPTH.value: "GraphQL Unbounded Query Depth DoS",
            GraphQLTechnique.FRAGMENT_RECURSION.value: "GraphQL Fragment Recursion DoS",
            GraphQLTechnique.BATCHING_ARRAY.value: "GraphQL HTTP Query Array Batching",
            GraphQLTechnique.BATCHING_ALIAS.value: "GraphQL Alias Multiplexing Abuse",
            GraphQLTechnique.FIELD_ACCESS_CONTROL.value: "GraphQL Broken Field-Level Access Control",
            GraphQLTechnique.INJECTION_SQLI.value: "GraphQL Argument SQL Injection",
            GraphQLTechnique.INJECTION_CMDI.value: "GraphQL Argument Command Injection",
        }
        title_base = technique_titles.get(result.technique, f"GraphQL Vulnerability ({result.technique})")
        title = f"{title_base}: {target_url}"

        description = (
            f"Confirmed {title_base} on {target_url} via {result.mutation_strategy} mutation. "
            f"Signature: {result.matched_signature}. Evidence snippet: {result.evidence_snippet[:150]}"
        )

        cwe_map = {
            GraphQLTechnique.INTROSPECTION.value: "CWE-200",
            GraphQLTechnique.TYPE_INTROSPECTION.value: "CWE-200",
            GraphQLTechnique.FIELD_SUGGESTIONS.value: "CWE-200",
            GraphQLTechnique.QUERY_DEPTH.value: "CWE-400",
            GraphQLTechnique.FRAGMENT_RECURSION.value: "CWE-674",
            GraphQLTechnique.BATCHING_ARRAY.value: "CWE-799",
            GraphQLTechnique.BATCHING_ALIAS.value: "CWE-799",
            GraphQLTechnique.FIELD_ACCESS_CONTROL.value: "CWE-285",
            GraphQLTechnique.INJECTION_SQLI.value: "CWE-89",
            GraphQLTechnique.INJECTION_CMDI.value: "CWE-78",
        }
        cwe_id = cwe_map.get(result.technique, "CWE-200")

        cvss_scores = {
            GraphQLSeverity.CRITICAL.value: 9.8,
            GraphQLSeverity.HIGH.value: 8.6,
            GraphQLSeverity.MEDIUM.value: 5.3,
            GraphQLSeverity.LOW.value: 4.3,
            GraphQLSeverity.INFO.value: 0.0,
        }
        cvss_score = cvss_scores.get(result.severity, 5.3)

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="graphql_security",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            provenance=ProvenanceData(
                step_id="graphql_security_collector",
            ),
            tags=[
                "graphql",
                "graphql_security",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "graphql_security",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": result.payload[:300],
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
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
                "mutation_strategy": result.mutation_strategy,
                "cwe_id": cwe_id,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
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

        # 4. ControlledMission Wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active GraphQL security testing against discovered candidate endpoints.
        """
        candidates = self._discover_candidate_endpoints(mission)
        if not candidates:
            logger.info("GraphQLSecurityCollector: No candidate GraphQL endpoints found.")
            return []

        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        strategies_to_test = [
            GraphQLMutationStrategy.STANDARD,
            GraphQLMutationStrategy.METHOD_SWAPPING,
            GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION,
            GraphQLMutationStrategy.QUERY_OBFUSCATION,
            GraphQLMutationStrategy.ALIAS_POLLUTION,
            GraphQLMutationStrategy.VARIABLE_EXTRACTION,
            GraphQLMutationStrategy.DIRECTIVE_BYPASS,
        ]

        for cand in candidates:
            target_url = cand["url"]
            headers = cand.get("headers") or {}
            cookies = cand.get("cookies") or {}
            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Step 0: Baseline probe
            baseline_query = self.payload_generator.build_baseline_query()
            baseline_resp = self._execute_request(
                mission=mission,
                method="POST",
                url=target_url,
                json_data={"query": baseline_query},
                headers={"Content-Type": "application/json", **headers},
                cookies=cookies,
            )

            # Step 1: Introspection & Type Introspection Probes across mutation strategies
            introspection_query = self.payload_generator.build_introspection_query(full=True)
            for strat in strategies_to_test:
                f_key = f"{target_url}:{GraphQLTechnique.INTROSPECTION.value}:{strat.value}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=introspection_query,
                    strategy=strat,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_introspection(
                        response=resp,
                        baseline_response=baseline_resp,
                        technique=GraphQLTechnique.INTROSPECTION.value,
                        mutation_strategy=strat.value,
                        payload=introspection_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            # Targeted Type Introspection Probe
            type_query = self.payload_generator.build_type_introspection_query("Query")
            resp_type = self._dispatch_mutation(
                mission=mission,
                target_url=target_url,
                query=type_query,
                strategy=GraphQLMutationStrategy.STANDARD,
                base_headers=headers,
                cookies=cookies,
            )
            if resp_type:
                res_type = self.analyzer.analyze_introspection(
                    response=resp_type,
                    baseline_response=baseline_resp,
                    technique=GraphQLTechnique.TYPE_INTROSPECTION.value,
                    mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                    payload=type_query,
                    endpoint_url=target_url,
                )
                if res_type and res_type.is_valid_finding:
                    f_key = f"{target_url}:{GraphQLTechnique.TYPE_INTROSPECTION.value}"
                    if f_key not in confirmed_findings:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res_type,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 2: Field Suggestion Leakage Probes
            for probe in self.payload_generator.build_suggestion_probes():
                f_key = f"{target_url}:{GraphQLTechnique.FIELD_SUGGESTIONS.value}:{probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_field_suggestions(
                        response=resp,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=probe["query"],
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            # Step 3: Query Depth Probes (5, 10, 15)
            for depth in (5, 10, 15):
                f_key = f"{target_url}:{GraphQLTechnique.QUERY_DEPTH.value}:{depth}"
                if f_key in confirmed_findings:
                    continue

                depth_query = self.payload_generator.build_depth_query(depth=depth)
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=depth_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_query_depth(
                        response=resp,
                        depth=depth,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=depth_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 4: Fragment Recursion Probes
            frag_query = self.payload_generator.build_fragment_cycle_query()
            f_key = f"{target_url}:{GraphQLTechnique.FRAGMENT_RECURSION.value}"
            if f_key not in confirmed_findings:
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=frag_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_fragment_recursion(
                        response=resp,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=frag_query,
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 5: Batching & Multiplexing Probes
            # 5A: HTTP Query Array Batching
            batch_payload = self.payload_generator.build_batch_array_payload(count=3)
            f_key = f"{target_url}:{GraphQLTechnique.BATCHING_ARRAY.value}"
            if f_key not in confirmed_findings:
                resp = self._execute_request(
                    mission=mission,
                    method="POST",
                    url=target_url,
                    json_data=batch_payload,
                    headers={"Content-Type": "application/json", **headers},
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_batching_array(
                        response=resp,
                        batch_size=3,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=json.dumps(batch_payload),
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # 5B: Alias Multiplexing
            alias_query = self.payload_generator.build_alias_multiplexing_query(alias_count=20)
            f_key = f"{target_url}:{GraphQLTechnique.BATCHING_ALIAS.value}"
            if f_key not in confirmed_findings:
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=alias_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_alias_multiplexing(
                        response=resp,
                        alias_count=20,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=alias_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 6: Field-Level Access Control (BOPLA) Probes
            for auth_probe in self.payload_generator.build_field_authorization_probes():
                f_name = auth_probe["field"]
                f_key = f"{target_url}:{GraphQLTechnique.FIELD_ACCESS_CONTROL.value}:{f_name}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=auth_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_field_access_control(
                        response=resp,
                        sensitive_field=f_name,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=auth_probe["query"],
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 7: Argument Injection Probes (SQLi & CmdI)
            for sqli_probe in self.payload_generator.build_sqli_probes():
                f_key = f"{target_url}:{GraphQLTechnique.INJECTION_SQLI.value}:{sqli_probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=sqli_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_injection(
                        response=resp,
                        injection_type="sqli",
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=sqli_probe["payload"],
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            for cmdi_probe in self.payload_generator.build_cmdi_probes():
                f_key = f"{target_url}:{GraphQLTechnique.INJECTION_CMDI.value}:{cmdi_probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=cmdi_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_injection(
                        response=resp,
                        injection_type="cmdi",
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=cmdi_probe["payload"],
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

        return detected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter execution entry point."""
        return self.collect(mission)


# Exported Aliases
GraphQLCollector = GraphQLSecurityCollector
