"""XML Parser Configuration Security Collector for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.xml_parser.models import (
    PARSER_ERROR_SIGNATURES,
    TARGET_FILE_SIGNATURES,
    XMLMutationStrategy,
    XMLTechnique,
    XMLValidationResult,
)
from argus.collectors.xml_parser.payloads import (
    XMLPayloadGenerator,
)
from argus.collectors.xml_parser.analyzer import (
    XMLParserAnalyzer,
)
from argus.collectors.xml_parser.collector import (
    XMLParserSecurityCollector,
    XMLParserValidationCollector,
    XXECollector,
)
__all__ = [
    "PARSER_ERROR_SIGNATURES",
    "TARGET_FILE_SIGNATURES",
    "XMLMutationStrategy",
    "XMLParserAnalyzer",
    "XMLParserSecurityCollector",
    "XMLParserValidationCollector",
    "XMLPayloadGenerator",
    "XMLTechnique",
    "XMLValidationResult",
    "XXECollector",
]
