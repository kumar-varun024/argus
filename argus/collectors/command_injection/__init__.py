"""OS command-injection detection collector (split into a cohesive sub-package).

Re-exports the classes, the result model, ``Severity``, and every module-level
constant so ``from argus.collectors.command_injection import ...`` is unchanged.
"""
from argus.collectors.toolkit.enums import Severity
from argus.collectors.command_injection.models import (
    CommandInjectionResult,
    OS_RESULT_SIGNATURES,
    SHELL_ERROR_SIGNATURES,
    RESULT_COMMAND_PAYLOADS,
    DEFAULT_TIME_DELAY_PAYLOADS,
    DEFAULT_ERROR_TRIGGER_PAYLOADS,
    COMMON_CMDI_PARAMS,
    DEFAULT_CMDI_PROBE_ROUTES,
)
from argus.collectors.command_injection.payloads import CommandInjectionPayloadGenerator
from argus.collectors.command_injection.analyzer import CommandInjectionAnalyzer
from argus.collectors.command_injection.collector import CommandInjectionCollector

__all__ = [
    "CommandInjectionCollector",
    "CommandInjectionAnalyzer",
    "CommandInjectionPayloadGenerator",
    "CommandInjectionResult",
    "Severity",
    "OS_RESULT_SIGNATURES",
    "SHELL_ERROR_SIGNATURES",
    "RESULT_COMMAND_PAYLOADS",
    "DEFAULT_TIME_DELAY_PAYLOADS",
    "DEFAULT_ERROR_TRIGGER_PAYLOADS",
    "COMMON_CMDI_PARAMS",
    "DEFAULT_CMDI_PROBE_ROUTES",
]
