"""xml_parser: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class XMLTechnique(str, Enum):
    """Enumeration of XML parser validation techniques."""
    ENTITY_RESOLUTION = "entity_resolution"
    PARAMETER_ENTITY = "parameter_entity"
    RECURSIVE_ENTITY = "recursive_entity"
    XINCLUDE = "xinclude"

class XMLMutationStrategy(str, Enum):
    """Enumeration of parser configuration bypass mutation strategies."""
    DOCTYPE_SYSTEM = "doctype_system"
    DOCTYPE_PUBLIC = "doctype_public"
    UTF16_ENCODING = "utf16_encoding"
    UTF7_ENCODING = "utf7_encoding"
    CDATA_WRAPPING = "cdata_wrapping"
    DOCTYPE_VARIATIONS = "doctype_variations"
    NAMESPACE_SOAP = "namespace_soap"
    XINCLUDE = "xinclude"
    URI_SCHEMES = "uri_schemes"

@dataclass
class XMLValidationResult:
    """Represents the parsed outcome of an XML validation probe."""
    technique: str
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    target_file: Optional[str] = None
    status_code: int = 200
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "xxe"

TARGET_FILE_SIGNATURES: Dict[str, re.Pattern] = {
    "unix_passwd": re.compile(
        r"root:[x*]?:0:0:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+)",
        re.MULTILINE,
    ),
    "unix_shadow": re.compile(
        r"(?m)^root:(?:\$[0-9a-zA-Z$=_./-]+|!|\*):[0-9]*:[0-9]*:[0-9]*:[0-9]*:"
    ),
    "unix_hosts": re.compile(r"(?m)^127\.0\.0\.1\s+localhost"),
    "unix_version": re.compile(r"Linux version \d+\.\d+[\w\.-]+ \([^\)]+\)"),
    "unix_hostname": re.compile(
        r"^(?:[a-zA-Z0-9][-a-zA-Z0-9_.]*)$",
        re.MULTILINE,
    ),
    "windows_win_ini": re.compile(
        r"\[(?:fonts|extensions|mci extensions|files|mail|386enh|drivers)\]",
        re.IGNORECASE,
    ),
    "windows_boot_ini": re.compile(
        r"\[(?:boot loader|operating systems)\]",
        re.IGNORECASE,
    ),
}

PARSER_ERROR_SIGNATURES: Dict[str, re.Pattern] = {
    # Java / Xerces / SAX
    "java_entity_expansion_limit": re.compile(
        r"(?:The parser has reached the entity expansion limit|entity expansion limit.*exceeded|Excessive entity expansion)",
        re.IGNORECASE,
    ),
    "java_disallow_doctype": re.compile(
        r"DOCTYPE is disallowed when the feature \"http://apache\.org/xml/features/disallow-doctype-decl\" is set to true",
        re.IGNORECASE,
    ),
    "java_file_not_found_entity": re.compile(
        r"java\.io\.FileNotFoundException:.*(?:/etc/|win\.ini|nonexistent)",
        re.IGNORECASE,
    ),
    # Libxml2 (PHP / Python lxml / C)
    "libxml2_entity_amplification": re.compile(
        r"(?:Maximum entity amplification factor limit exceeded|XML_PARSE_HUGE|parser error : Maximum entity amplification)",
        re.IGNORECASE,
    ),
    "libxml2_external_entity_error": re.compile(
        r"warning: failed to load external entity \"file:///",
        re.IGNORECASE,
    ),
    # .NET Framework / Core
    "dotnet_max_chars_from_entities": re.compile(
        r"The input document has exceeded a limit set by MaxCharactersFromEntities",
        re.IGNORECASE,
    ),
    "dotnet_dtd_prohibited": re.compile(
        r"For security reasons DTD is prohibited in this XML document",
        re.IGNORECASE,
    ),
    # Python defusedxml / standard xml
    "python_defusedxml_forbidden": re.compile(
        r"(?:EntitiesForbidden|DTDForbidden|SuspiciousOperation)",
        re.IGNORECASE,
    ),
}
