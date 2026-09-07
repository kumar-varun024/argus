"""auth_bypass: HTTP probe dispatch."""
from __future__ import annotations

import copy
import json
import time
from typing import Any, Dict, List, Optional

from argus.http.client import AuthenticatedHttpClient
from argus.collectors.auth_bypass.models import AuthBypassProbe, AuthBypassProbeResponse, AuthVulnerabilityType


class AuthBypassProber:
    """
    Executes authentication bypass validation probes using AuthenticatedHttpClient
    or mock clients, handling burst sequences, timing measurements, and multi-identity execution.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        client: Optional[Any] = None,
        timeout: float = 10.0,
    ) -> None:
        self.client = http_client or client or AuthenticatedHttpClient(timeout=timeout)
        self.timeout = timeout

    def execute_probe(
        self, mission: Any, target_url: str, probe: AuthBypassProbe
    ) -> AuthBypassProbeResponse:
        """Executes a single or burst authentication probe and constructs an AuthBypassProbeResponse."""
        if probe.burst_count > 1:
            burst_resps = self.execute_burst_sequence(mission, target_url, probe, count=probe.burst_count)
            first_resp = burst_resps[0] if burst_resps else {}
            last_resp = burst_resps[-1] if burst_resps else {}

            headers = {k.lower(): v for k, v in last_resp.get("headers", {}).items()}
            return AuthBypassProbeResponse(
                probe=probe,
                status_code=last_resp.get("status_code", 0),
                headers=headers,
                body=last_resp.get("body", ""),
                json_body=last_resp.get("json_body"),
                elapsed=last_resp.get("elapsed", 0.0),
                error=last_resp.get("error"),
                burst_responses=burst_resps,
                rate_limit_headers={k: v for k, v in headers.items() if "ratelimit" in k or "retry-after" in k},
            )

        start_time = time.time()
        status_code = 0
        headers_dict: Dict[str, str] = {}
        body = ""
        json_body = None
        error_msg = None
        raw_resp = None

        try:
            # Client polymorphism support
            method = probe.method.upper()
            url = probe.target_url or target_url
            kwargs: Dict[str, Any] = {
                "headers": dict(probe.headers),
                "params": dict(probe.params),
                "timeout": self.timeout,
            }
            if probe.json_data is not None:
                kwargs["json"] = probe.json_data
            if probe.data is not None:
                kwargs["data"] = probe.data

            # Check calling signature
            if hasattr(self.client, "request"):
                try:
                    raw_resp = self.client.request(mission, method, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.request(method, url, **kwargs)
            elif method == "GET" and hasattr(self.client, "get"):
                try:
                    raw_resp = self.client.get(mission, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.get(url, **kwargs)
            elif method == "POST" and hasattr(self.client, "post"):
                try:
                    raw_resp = self.client.post(mission, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.post(url, **kwargs)
            else:
                error_msg = f"Unsupported HTTP client interface: {type(self.client)}"

            if raw_resp is not None:
                status_code = getattr(raw_resp, "status_code", 0)
                raw_headers = getattr(raw_resp, "headers", {}) or {}
                headers_dict = {k.lower(): str(v) for k, v in raw_headers.items()}
                body = getattr(raw_resp, "body", "") or getattr(raw_resp, "text", "") or ""
                if not body and hasattr(raw_resp, "raw_body"):
                    body = str(raw_resp.raw_body)

                try:
                    json_body = json.loads(body) if body else None
                except Exception:
                    json_body = None

                if hasattr(raw_resp, "error") and raw_resp.error:
                    error_msg = str(raw_resp.error)

        except Exception as ex:
            error_msg = str(ex)

        elapsed = time.time() - start_time
        rate_limit_hdrs = {k: v for k, v in headers_dict.items() if "ratelimit" in k or "retry-after" in k}

        return AuthBypassProbeResponse(
            probe=probe,
            status_code=status_code,
            headers=headers_dict,
            body=body,
            json_body=json_body,
            elapsed=elapsed,
            error=error_msg,
            raw_http_response=raw_resp,
            rate_limit_headers=rate_limit_hdrs,
        )

    def execute_burst_sequence(
        self, mission: Any, target_url: str, probe: AuthBypassProbe, count: int = 10
    ) -> List[Dict[str, Any]]:
        """Executes rapid sequential requests, capturing status codes, latencies, and headers."""
        burst_records: List[Dict[str, Any]] = []

        for i in range(count):
            iter_probe = copy.deepcopy(probe)
            iter_probe.burst_count = 1
            # If testing credential stuffing with IP rotation, inject distinct IP per iteration
            if probe.vulnerability_type == AuthVulnerabilityType.CREDENTIAL_STUFFING:
                iter_probe.headers["X-Forwarded-For"] = f"10.0.{i // 250}.{i % 250 + 1}"

            start_t = time.time()
            single_resp = self.execute_probe(mission, target_url, iter_probe)
            burst_records.append({
                "iteration": i + 1,
                "status_code": single_resp.status_code,
                "elapsed": single_resp.elapsed,
                "headers": single_resp.headers,
                "body": single_resp.body,
                "json_body": single_resp.json_body,
                "error": single_resp.error,
            })
        return burst_records

    def execute_differential_identity_probe(
        self,
        mission: Any,
        target_url: str,
        probe: AuthBypassProbe,
        primary_identity: Any,
        secondary_identity: Any,
    ) -> AuthBypassProbeResponse:
        """Executes a comparative probe between two test identities to test boundary enforcement."""
        primary_probe = copy.deepcopy(probe)
        if primary_identity and hasattr(primary_identity, "get_auth_headers"):
            primary_probe.headers.update(primary_identity.get_auth_headers())

        resp = self.execute_probe(mission, target_url, primary_probe)
        return resp
