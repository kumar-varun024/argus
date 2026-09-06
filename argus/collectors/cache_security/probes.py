"""cache_security: HTTP probe dispatch."""
from __future__ import annotations

import logging
import time
import urllib.parse
import uuid
from typing import Any, Dict, Optional

from argus.http.client import AuthenticatedHttpClient
from argus.collectors.cache_security.models import CacheProbe, CacheProbeResponse, CacheVulnerabilityType, _DEFAULT
from argus.collectors.cache_security.analyzer import CacheSecurityAnalyzer

logger = logging.getLogger(__name__)


class CacheSecurityProber:
    """
    Executes sequential differential cache verification requests
    (Baseline B0 -> Perturbation B1 -> Replay B1 -> Isolation Control B2).
    """

    def __init__(self, http_client: Optional[Any] = None, timeout: float = 10.0):
        self.http_client = http_client
        self.timeout = timeout

    def generate_nonce(self, prefix: str = "cb") -> str:
        """Generates a randomized cache buster nonce."""
        return f"{prefix}_{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"

    def _prepare_url_with_nonce(self, base_url: str, nonce: str, path_suffix: str = "", extra_params: Optional[Dict[str, str]] = None) -> str:
        """Constructs target URL appending path suffix and cache buster nonces."""
        parsed = urllib.parse.urlparse(base_url)
        path = parsed.path
        if path_suffix:
            if path_suffix.startswith("/") and path.endswith("/"):
                path = path[:-1] + path_suffix
            elif not path_suffix.startswith("/") and not path_suffix.startswith(";") and not path.endswith("/"):
                path = path + "/" + path_suffix
            else:
                path = path + path_suffix

        # Query parameters
        existing_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_dict = dict(existing_params)
        query_dict["cb"] = nonce
        if extra_params:
            query_dict.update(extra_params)

        new_query = urllib.parse.urlencode(query_dict)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    def send_probe_request(
        self,
        url: str,
        probe: CacheProbe,
        headers: Any = _DEFAULT,
        body: Any = _DEFAULT,
        method: Any = _DEFAULT,
        auth_identity: Optional[Any] = None,
    ) -> CacheProbeResponse:
        """Dispatches an HTTP request and converts the response to a CacheProbeResponse."""
        effective_method = (probe.method if method is _DEFAULT else (method or "GET")).upper()
        effective_headers = dict(probe.headers if headers is _DEFAULT else (headers or {}))
        effective_body = probe.body if body is _DEFAULT else body

        start_time = time.time()
        status_code = 0
        resp_headers: Dict[str, str] = {}
        resp_body = ""
        raw_body = ""

        try:
            if self.http_client is not None:
                # Use provided client (mock or custom)
                if hasattr(self.http_client, "request"):
                    res = self.http_client.request(effective_method, url, headers=effective_headers, data=effective_body, timeout=self.timeout)
                elif effective_method == "POST" and hasattr(self.http_client, "post"):
                    res = self.http_client.post(url, headers=effective_headers, data=effective_body, timeout=self.timeout)
                elif hasattr(self.http_client, "get"):
                    res = self.http_client.get(url, headers=effective_headers, timeout=self.timeout)
                else:
                    res = None

                if res is not None:
                    status_code = getattr(res, "status_code", 200) or 200
                    resp_headers = {k.lower(): str(v) for k, v in getattr(res, "headers", {}).items()}
                    resp_body = getattr(res, "body", "") or getattr(res, "text", "") or ""
                    raw_body = getattr(res, "raw_body", "") or resp_body
            else:
                # Use AuthenticatedHttpClient
                with AuthenticatedHttpClient(timeout=self.timeout) as client:
                    if effective_method == "POST":
                        res = client.post(url, headers=effective_headers, data=effective_body, identity=auth_identity)
                    else:
                        res = client.get(url, headers=effective_headers, identity=auth_identity)

                    if res is not None:
                        status_code = res.status_code or 0
                        resp_headers = {k.lower(): str(v) for k, v in (res.headers or {}).items()}
                        resp_body = res.body or ""
                        raw_body = res.raw_body or resp_body
        except Exception as e:
            logger.debug("CacheSecurityProber request exception for %s: %s", url, e)

        elapsed = time.time() - start_time

        # Analyze cache status and engine
        status, engine, age = CacheSecurityAnalyzer.analyze_cache_lifecycle(resp_headers)

        # Check canary presence
        canary_in_body = False
        canary_in_headers = False
        if probe.canary:
            canary_in_body = probe.canary in resp_body or probe.canary in raw_body
            canary_in_headers = any(probe.canary in v for v in resp_headers.values())

        # Check PII presence
        pii_detected, pii_matches = CacheSecurityAnalyzer.detect_pii(raw_body or resp_body)

        location_header = resp_headers.get("location")

        return CacheProbeResponse(
            probe=probe,
            status_code=status_code,
            headers=resp_headers,
            body=resp_body,
            raw_body=raw_body,
            elapsed=elapsed,
            cache_status=status,
            engine=engine,
            age=age,
            canary_in_body=canary_in_body,
            canary_in_headers=canary_in_headers,
            pii_detected=pii_detected,
            pii_matches=pii_matches,
            location_header=location_header,
        )

    def execute_differential_sequence(
        self,
        base_url: str,
        probe: CacheProbe,
        baseline_nonce: Optional[str] = None,
        probe_nonce: Optional[str] = None,
        control_nonce: Optional[str] = None,
        auth_identity: Optional[Any] = None,
    ) -> Dict[str, CacheProbeResponse]:
        """
        Executes the 4-step differential confirmation sequence:
        1. Baseline: Clean request with Nonce B0
        2. Perturbation: Injected probe request with Nonce B1
        3. Replay: Clean request (no poison headers / unauth) with Nonce B1
        4. Isolation Control: Clean request with Nonce B2
        """
        b0 = baseline_nonce or self.generate_nonce("b0")
        b1 = probe_nonce or self.generate_nonce("b1")
        b2 = control_nonce or self.generate_nonce("b2")

        # Step 1: Baseline measurement (Nonce B0)
        url_b0 = self._prepare_url_with_nonce(base_url, b0)
        resp_b0 = self.send_probe_request(
            url=url_b0,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=auth_identity if probe.is_auth_required else None,
        )

        # Step 2: Perturbation probe (Nonce B1)
        url_b1 = self._prepare_url_with_nonce(base_url, b1, path_suffix=probe.path_suffix, extra_params=probe.params)
        resp_b1 = self.send_probe_request(
            url=url_b1,
            probe=probe,
            headers=probe.headers,
            body=probe.body,
            method=probe.method,
            auth_identity=auth_identity if probe.is_auth_required else None,
        )

        # Step 3: Replay verification probe without poisoning headers (Nonce B1)
        # For WCD, replay is done WITHOUT authentication to test unauthenticated cache exposure!
        url_replay = self._prepare_url_with_nonce(base_url, b1, path_suffix=probe.path_suffix if probe.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION else "")
        resp_replay = self.send_probe_request(
            url=url_replay,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=None,  # Unauthenticated victim replay
        )

        # Step 4: Isolation control probe (Nonce B2)
        url_b2 = self._prepare_url_with_nonce(base_url, b2)
        resp_b2 = self.send_probe_request(
            url=url_b2,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=None,
        )

        return {
            "baseline": resp_b0,
            "perturbed": resp_b1,
            "replay": resp_replay,
            "control": resp_b2,
        }
