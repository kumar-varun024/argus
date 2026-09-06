"""SQL injection detection collector (split into a cohesive sub-package).

Public names — the three classes and the module-level payload/signature
constants — are re-exported so ``from argus.collectors.sql_injection import ...``
keeps working unchanged.
"""
from argus.collectors.sql_injection.models import (
    DBMS_ERROR_SIGNATURES,
    DEFAULT_ERROR_PAYLOADS,
    DEFAULT_BOOLEAN_PAIRS,
    DEFAULT_TIME_PAYLOADS_TEMPLATE,
    COMMON_SQL_PARAMS,
    DEFAULT_SQLI_PROBE_ROUTES,
)
from argus.collectors.sql_injection.payloads import SQLInjectionPayloadGenerator
from argus.collectors.sql_injection.analyzer import SQLInjectionAnalyzer
from argus.collectors.sql_injection.collector import SQLInjectionCollector

__all__ = [
    "SQLInjectionCollector",
    "SQLInjectionAnalyzer",
    "SQLInjectionPayloadGenerator",
    "DBMS_ERROR_SIGNATURES",
    "DEFAULT_ERROR_PAYLOADS",
    "DEFAULT_BOOLEAN_PAIRS",
    "DEFAULT_TIME_PAYLOADS_TEMPLATE",
    "COMMON_SQL_PARAMS",
    "DEFAULT_SQLI_PROBE_ROUTES",
]
