"""XSS reflection/context analysis and false-positive suppression."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.xss.models import XSSContext


class _HTMLContextDetectorParser(HTMLParser):
    """
    Internal HTMLParser state machine for detecting the syntactic context of canary tokens.
    """

    def __init__(self, canary: str, raw_html: str):
        super().__init__()
        self.canary = canary
        self.raw_html = raw_html
        self.detected_context: XSSContext = XSSContext.UNKNOWN
        self.in_script: bool = False
        self.in_style: bool = False
        self.current_tag: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        self.current_tag = tag_lower
        if tag_lower == "script":
            self.in_script = True
        elif tag_lower == "style":
            self.in_style = True

        for attr_name, attr_value in attrs:
            if attr_value and self.canary in attr_value:
                attr_name_lower = attr_name.lower()
                if attr_name_lower in ("href", "src", "action", "formaction", "data") and attr_value.strip().lower().startswith("javascript:"):
                    self.detected_context = XSSContext.URL_ATTRIBUTE
                    return

                # Distinguish quoting style for this attribute
                attr_pattern = re.compile(
                    r'\b' + re.escape(attr_name) + r'\s*=\s*(["\']?)[^"\'\s>]*?' + re.escape(self.canary),
                    re.IGNORECASE,
                )
                m = attr_pattern.search(self.raw_html)
                if m:
                    quote_char = m.group(1)
                    if quote_char == '"':
                        self.detected_context = XSSContext.ATTRIBUTE_DOUBLE
                    elif quote_char == "'":
                        self.detected_context = XSSContext.ATTRIBUTE_SINGLE
                    else:
                        self.detected_context = XSSContext.ATTRIBUTE_UNQUOTED
                else:
                    self.detected_context = XSSContext.ATTRIBUTE_DOUBLE
                return

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "script":
            self.in_script = False
        elif tag_lower == "style":
            self.in_style = False
        self.current_tag = None

    def handle_data(self, data: str):
        if self.canary in data:
            if self.in_script:
                if f'"{self.canary}' in data or f'{self.canary}"' in data:
                    self.detected_context = XSSContext.SCRIPT_STRING_DOUBLE
                elif f"'{self.canary}" in data or f"{self.canary}'" in data:
                    self.detected_context = XSSContext.SCRIPT_STRING_SINGLE
                elif f"`{self.canary}" in data or f"{self.canary}`" in data:
                    self.detected_context = XSSContext.SCRIPT_STRING_DOUBLE
                else:
                    self.detected_context = XSSContext.SCRIPT_BLOCK
            elif not self.in_style:
                self.detected_context = XSSContext.HTML_BODY

    def handle_comment(self, data: str):
        if self.canary in data:
            self.detected_context = XSSContext.COMMENT


class XSSAnalyzer:
    """
    Parses and inspects HTTP responses for unescaped XSS reflections and persistence,
    strictly suppressing false positives when characters are entity-encoded.
    """

    # HTML Entity patterns
    ENTITY_PATTERNS = [
        re.compile(r"&(?:lt|#0*60|#x0*3c);", re.IGNORECASE),
        re.compile(r"&(?:gt|#0*62|#x0*3e);", re.IGNORECASE),
        re.compile(r"&(?:quot|#0*34|#x0*22);", re.IGNORECASE),
        re.compile(r"&(?:apos|#0*39|#x0*27);", re.IGNORECASE),
        re.compile(r"&(?:amp|#0*38|#x0*26);", re.IGNORECASE),
    ]

    NON_HTML_CONTENT_TYPES = [
        "application/json",
        "text/plain",
        "application/xml",
        "text/xml",
        "application/javascript",
        "text/javascript",
        "text/css",
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "application/octet-stream",
        "application/zip",
        "application/x-tar",
        "application/gzip",
    ]

    def is_properly_escaped(self, body: str, canary: str) -> bool:
        """
        Strictly checks whether special characters associated with the canary are HTML
        entity-encoded (&lt;, &gt;, &quot;, &#39;, &#x27;, &amp;), suppressing false positives.
        Returns True if the output is safely escaped, False if unescaped/vulnerable.
        """
        if not body or canary not in body:
            return True

        start = 0
        has_vulnerable_occurrence = False

        while True:
            idx = body.find(canary, start)
            if idx == -1:
                break

            before_canary = body[max(0, idx - 150):idx]

            # Extract all tags (both raw <tag and encoded &lt;tag) in before_canary
            tag_matches = list(re.finditer(
                r"(&(?:lt|#0*60|#x0*3c);|<)(/?)([a-zA-Z0-9]+)",
                before_canary,
                re.IGNORECASE,
            ))

            is_escaped = False
            if tag_matches:
                last_match = tag_matches[-1]
                last_tag_prefix = last_match.group(1)
                last_is_closing = bool(last_match.group(2))
                last_tag_name = last_match.group(3).lower()

                # If the last tag before canary was encoded with &lt;
                if last_tag_prefix.startswith("&"):
                    is_escaped = True
                elif last_tag_name in ("script", "img", "svg", "iframe", "b", "a", "body") and not last_is_closing:
                    # Raw dangerous tag directly enclosing or preceding the canary
                    has_vulnerable_occurrence = True
                    start = idx + len(canary)
                    continue

            # Check for attribute quote breakout and script execution (raw vs encoded)
            if not is_escaped:
                has_raw_breakout = bool(re.search(r'(?<!&quot;)(?<!&#34;)(?<!&#x22;)(?<!&#39;)(?<!&#x27;)["\']>\s*<(?:script|img|svg|iframe|b|a)\b', before_canary, re.IGNORECASE))
                has_raw_event = bool(re.search(r'(?<!&quot;)(?<!&#34;)(?<!&#x22;)(?<!&#39;)(?<!&#x27;)["\']\s*(?:on\w+|autofocus)\s*=\s*["\']?', before_canary, re.IGNORECASE))
                has_raw_unquoted_event = bool(re.search(r'\s+(?:on\w+|autofocus)\s*=\s*[^"\'\s>&]+', before_canary, re.IGNORECASE))
                has_raw_script_call = bool(re.search(r'(?:alert|confirm|prompt|console\.log)\s*\(', before_canary, re.IGNORECASE)) and ("<script" in before_canary and not re.search(r"&(?:lt|#0*60|#x0*3c);script", before_canary, re.IGNORECASE))
                has_raw_js_url = bool(re.search(r'(?:href|src|action)\s*=\s*["\']?javascript:[^"\'>]*?$', before_canary, re.IGNORECASE))

                if has_raw_breakout or has_raw_event or has_raw_unquoted_event or has_raw_script_call or has_raw_js_url:
                    has_vulnerable_occurrence = True

            start = idx + len(canary)

        if has_vulnerable_occurrence:
            return False

        return True

    def detect_context(self, raw_body: str, canary: str) -> XSSContext:
        """
        Parses raw HTML to identify the exact syntactic context of the canary reflection.
        """
        if not raw_body or canary not in raw_body:
            return XSSContext.UNKNOWN

        try:
            parser = _HTMLContextDetectorParser(canary, raw_body)
            parser.feed(raw_body)
            if parser.detected_context != XSSContext.UNKNOWN:
                return parser.detected_context
        except Exception as e:
            logger.debug(f"HTMLContextDetectorParser exception: {e}")

        # Fallback regex heuristics
        if re.search(r"<script[^>]*>[^<]*?" + re.escape(canary), raw_body, re.IGNORECASE):
            idx = raw_body.find(canary)
            snippet = raw_body[max(0, idx - 40):min(len(raw_body), idx + len(canary) + 40)]
            if "'" in snippet:
                return XSSContext.SCRIPT_STRING_SINGLE
            elif '"' in snippet:
                return XSSContext.SCRIPT_STRING_DOUBLE
            return XSSContext.SCRIPT_BLOCK

        if re.search(r'<[^>]+(?:href|src|action)=["\']?javascript:[^>]*?' + re.escape(canary), raw_body, re.IGNORECASE):
            return XSSContext.URL_ATTRIBUTE

        if re.search(r'<[^>]+\w+=["\'][^"\']*?' + re.escape(canary), raw_body, re.IGNORECASE):
            idx = raw_body.find(canary)
            snippet = raw_body[max(0, idx - 40):min(len(raw_body), idx + len(canary) + 40)]
            if "'" in snippet:
                return XSSContext.ATTRIBUTE_SINGLE
            return XSSContext.ATTRIBUTE_DOUBLE

        if re.search(r'<[^>]+\w+=[^"\'\s>]*?' + re.escape(canary), raw_body, re.IGNORECASE):
            return XSSContext.ATTRIBUTE_UNQUOTED

        if re.search(r'<!--[^>]*?' + re.escape(canary), raw_body):
            return XSSContext.COMMENT

        return XSSContext.HTML_BODY

    def analyze_reflected(
        self,
        resp: Optional[HttpResponse],
        canary: str,
        payload: str,
        context: Optional[XSSContext] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Verifies unescaped reflection and breakout in HTML body, attribute, script, or header context.
        Returns a structured finding dictionary on confirmation, or None if safe / false positive.
        """
        if resp is None:
            return None

        headers = getattr(resp, "headers", {}) or {}
        content_type = ""
        for hk, hv in headers.items():
            if hk.lower() == "content-type":
                content_type = hv.lower()
                break

        # Reject non-HTML/non-renderable content types
        if content_type:
            is_non_html = any(nht in content_type for nht in self.NON_HTML_CONTENT_TYPES)
            is_html_compatible = any(ht in content_type for ht in ("text/html", "application/xhtml+xml", "image/svg+xml"))
            if is_non_html and not is_html_compatible:
                return None

        raw_body = (
            getattr(resp, "raw_body", None)
            or getattr(resp, "body", None)
            or getattr(resp, "text", "")
            or ""
        )

        if not raw_body or canary not in raw_body:
            return None

        # Check entity-encoding false positive suppression
        if self.is_properly_escaped(raw_body, canary):
            return None

        # Detect syntactic context
        detected_context = context if (context is not None and context != XSSContext.UNKNOWN) else self.detect_context(raw_body, canary)

        # Context-specific breakout validation
        idx = raw_body.find(canary)
        snippet_start = max(0, idx - 80)
        snippet_end = min(len(raw_body), idx + len(canary) + 80)
        snippet = raw_body[snippet_start:snippet_end].strip()

        # Severity determination
        severity = "high"
        if detected_context == XSSContext.COMMENT or "header" in payload.lower():
            severity = "medium"

        template_id = f"xss-reflected-{detected_context.value.replace('_', '-')}"

        return {
            "xss_type": "reflected",
            "context": detected_context.value,
            "template_id": template_id,
            "severity": severity,
            "confidence": 0.95,
            "snippet": snippet,
            "payload": payload,
            "canary": canary,
        }

    def analyze_stored(
        self,
        resp: Optional[HttpResponse],
        canary: str,
        payload: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Verifies persistence of an unescaped XSS payload in a re-fetched page.
        Returns a structured finding dictionary with severity='critical' on confirmation.
        """
        if resp is None:
            return None

        headers = getattr(resp, "headers", {}) or {}
        content_type = ""
        for hk, hv in headers.items():
            if hk.lower() == "content-type":
                content_type = hv.lower()
                break

        if content_type:
            is_non_html = any(nht in content_type for nht in self.NON_HTML_CONTENT_TYPES)
            is_html_compatible = any(ht in content_type for ht in ("text/html", "application/xhtml+xml", "image/svg+xml"))
            if is_non_html and not is_html_compatible:
                return None

        raw_body = (
            getattr(resp, "raw_body", None)
            or getattr(resp, "body", None)
            or getattr(resp, "text", "")
            or ""
        )

        if not raw_body or canary not in raw_body:
            return None

        if self.is_properly_escaped(raw_body, canary):
            return None

        idx = raw_body.find(canary)
        snippet_start = max(0, idx - 80)
        snippet_end = min(len(raw_body), idx + len(canary) + 80)
        snippet = raw_body[snippet_start:snippet_end].strip()

        return {
            "xss_type": "stored",
            "context": "html_body",
            "template_id": "xss-stored",
            "severity": "critical",
            "confidence": 0.95,
            "snippet": snippet,
            "payload": payload,
            "canary": canary,
        }

