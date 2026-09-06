"""GraphQL Security Detection Collector for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.graphql.models import (
    BATCH_DEFENSE_SIGNATURES,
    COMMAND_OUTPUT_SIGNATURES,
    DEPTH_LIMIT_DEFENSE_SIGNATURES,
    FIELD_SUGGESTION_SIGNATURES,
    FRAGMENT_CYCLE_DEFENSE_SIGNATURES,
    GraphQLMutationStrategy,
    GraphQLSecurityResult,
    GraphQLSeverity,
    GraphQLTechnique,
    HARDENED_INTROSPECTION_SIGNATURES,
    INTROSPECTION_SIGNATURES,
    SENSITIVE_FIELD_NAMES,
    SQL_ERROR_SIGNATURES,
    Severity,
)
from argus.collectors.graphql.payloads import (
    GraphQLPayloadGenerator,
)
from argus.collectors.graphql.analyzer import (
    GraphQLSecurityAnalyzer,
)
from argus.collectors.graphql.collector import (
    GraphQLCollector,
    GraphQLSecurityCollector,
)
__all__ = [
    "BATCH_DEFENSE_SIGNATURES",
    "COMMAND_OUTPUT_SIGNATURES",
    "DEPTH_LIMIT_DEFENSE_SIGNATURES",
    "FIELD_SUGGESTION_SIGNATURES",
    "FRAGMENT_CYCLE_DEFENSE_SIGNATURES",
    "GraphQLCollector",
    "GraphQLMutationStrategy",
    "GraphQLPayloadGenerator",
    "GraphQLSecurityAnalyzer",
    "GraphQLSecurityCollector",
    "GraphQLSecurityResult",
    "GraphQLSeverity",
    "GraphQLTechnique",
    "HARDENED_INTROSPECTION_SIGNATURES",
    "INTROSPECTION_SIGNATURES",
    "SENSITIVE_FIELD_NAMES",
    "SQL_ERROR_SIGNATURES",
    "Severity",
]
