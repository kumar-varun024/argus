"""graphql: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from argus.collectors.toolkit.enums import Severity


GraphQLSeverity = Severity

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
