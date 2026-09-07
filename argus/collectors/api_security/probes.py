"""api_security: HTTP probe dispatch."""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.api_security.models import APIProbe, APIProbeResponse

logger = logging.getLogger(__name__)


class APISecurityProber:
    """
    Executes HTTP requests and burst sequences against API endpoints using AuthenticatedHttpClient.
    Handles headers, cookies, query parameters, JSON/form bodies, bursts, and differential identity probing.
    """

    def __init__(self, client: Optional[Any] = None, timeout: float = 10.0) -> None:
        self.client = client
        self.timeout = timeout

    def _get_client(self, mission: Any) -> Any:
        """Retrieves or creates an AuthenticatedHttpClient instance."""
        if self.client is not None:
            return self.client
        return AuthenticatedHttpClient(timeout=self.timeout)

    def execute_probe(self, mission: Any, target_url: str, probe: APIProbe) -> APIProbeResponse:
        """
        Executes a single API security probe against target_url.
        """
        client = self._get_client(mission)
        url = probe.target_url or target_url
        method = (probe.method or "GET").upper()
        headers = dict(probe.headers)
        params = dict(probe.params) if probe.params else None
        json_data = probe.json_data
        data = probe.data

        # If probe requests bursts, route to execute_burst_sequence
        if probe.burst_count > 1:
            return self.execute_burst_sequence(mission, url, probe, count=probe.burst_count)

        start_time = time.time()
        try:
            if hasattr(client, "request"):
                try:
                    resp = client.request(
                        mission,
                        method,
                        url,
                        headers=headers if headers else None,
                        params=params,
                        json=json_data,
                        data=data,
                        timeout=self.timeout,
                        action="api_security_probe",
                    )
                except TypeError:
                    try:
                        resp = client.request(
                            method,
                            url,
                            headers=headers if headers else None,
                            params=params,
                            json=json_data,
                            data=data,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        resp = client.request(
                            method=method,
                            url=url,
                            headers=headers if headers else None,
                            params=params,
                            json=json_data,
                            data=data,
                            timeout=self.timeout,
                        )
            elif hasattr(client, "get") and method == "GET":
                try:
                    resp = client.get(mission, url=url, headers=headers, params=params, timeout=self.timeout)
                except TypeError:
                    resp = client.get(url=url, headers=headers, params=params, timeout=self.timeout)
            elif hasattr(client, "post") and method == "POST":
                try:
                    resp = client.post(mission, url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
                except TypeError:
                    resp = client.post(url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            else:
                # Fallback generic call
                resp = None

            elapsed = time.time() - start_time

            if resp is None:
                return APIProbeResponse(
                    probe=probe,
                    status_code=0,
                    error="HttpClient returned None response",
                    elapsed=elapsed,
                )

            status_code = getattr(resp, "status_code", 0) or 0
            resp_headers = getattr(resp, "headers", {}) or {}
            if hasattr(resp_headers, "items"):
                resp_headers_dict = {str(k).lower(): str(v) for k, v in resp_headers.items()}
            else:
                resp_headers_dict = dict(resp_headers)

            body_text = getattr(resp, "body", "") or getattr(resp, "text", "") or ""
            if isinstance(body_text, bytes):
                try:
                    body_text = body_text.decode("utf-8", errors="replace")
                except Exception:
                    body_text = str(body_text)

            json_body = None
            try:
                if body_text and (body_text.strip().startswith("{") or body_text.strip().startswith("[")):
                    json_body = json.loads(body_text)
            except Exception:
                json_body = None

            return APIProbeResponse(
                probe=probe,
                status_code=status_code,
                headers=resp_headers_dict,
                body=body_text,
                json_body=json_body,
                elapsed=elapsed,
                error=getattr(resp, "error", None),
                raw_http_response=resp if isinstance(resp, HttpResponse) else None,
            )

        except Exception as ex:
            elapsed = time.time() - start_time
            logger.debug("API probe execution error against %s: %s", url, ex)
            return APIProbeResponse(
                probe=probe,
                status_code=0,
                error=str(ex),
                elapsed=elapsed,
            )

    def execute_burst_sequence(
        self, mission: Any, target_url: str, probe: APIProbe, count: int = 15
    ) -> APIProbeResponse:
        """
        Executes a rapid burst sequence of requests to test rate limiting enforcement and header bypasses.
        """
        client = self._get_client(mission)
        url = probe.target_url or target_url
        method = (probe.method or "GET").upper()
        headers = dict(probe.headers)
        params = dict(probe.params) if probe.params else None

        burst_results: List[Dict[str, Any]] = []
        last_resp = None
        rate_limit_headers: Dict[str, str] = {}
        rotate_ip = probe.metadata.get("rotate_ip", False)

        start_time = time.time()
        for idx in range(count):
            req_headers = dict(headers)
            if rotate_ip:
                spoofed_ip = f"198.51.100.{idx + 1}"
                req_headers["X-Forwarded-For"] = spoofed_ip
                req_headers["X-Real-IP"] = spoofed_ip
                req_headers["Client-IP"] = spoofed_ip

            try:
                if hasattr(client, "request"):
                    try:
                        resp = client.request(
                            mission,
                            method,
                            url,
                            headers=req_headers if req_headers else None,
                            params=params,
                            json=probe.json_data,
                            data=probe.data,
                            timeout=self.timeout,
                            action="rate_limit_burst",
                        )
                    except TypeError:
                        try:
                            resp = client.request(
                                method,
                                url,
                                headers=req_headers if req_headers else None,
                                params=params,
                                json=probe.json_data,
                                data=probe.data,
                                timeout=self.timeout,
                            )
                        except TypeError:
                            resp = client.request(
                                method=method,
                                url=url,
                                headers=req_headers if req_headers else None,
                                params=params,
                                json=probe.json_data,
                                data=probe.data,
                                timeout=self.timeout,
                            )
                else:
                    resp = None

                st = getattr(resp, "status_code", 0) or 0
                resp_hdrs = getattr(resp, "headers", {}) or {}
                if hasattr(resp_hdrs, "items"):
                    rh_dict = {str(k).lower(): str(v) for k, v in resp_hdrs.items()}
                else:
                    rh_dict = dict(resp_hdrs)

                # Collect rate limit headers
                for k, v in rh_dict.items():
                    if "ratelimit" in k or "retry-after" in k:
                        rate_limit_headers[k] = str(v)

                burst_results.append({
                    "request_index": idx + 1,
                    "status_code": st,
                    "headers": rh_dict,
                })
                last_resp = resp
            except Exception as ex:
                burst_results.append({
                    "request_index": idx + 1,
                    "status_code": 0,
                    "error": str(ex),
                })

        elapsed = time.time() - start_time
        final_status = getattr(last_resp, "status_code", 200) if last_resp else (burst_results[-1]["status_code"] if burst_results else 0)
        final_body = getattr(last_resp, "body", "") if last_resp else ""

        return APIProbeResponse(
            probe=probe,
            status_code=final_status,
            headers=rate_limit_headers,
            body=str(final_body),
            elapsed=elapsed,
            burst_responses=burst_results,
            rate_limit_headers=rate_limit_headers,
            raw_http_response=last_resp if isinstance(last_resp, HttpResponse) else None,
        )

    def execute_differential_identity_probe(
        self, mission: Any, target_url: str, probe: APIProbe
    ) -> APIProbeResponse:
        """
        Executes a differential probe to test authorization boundaries across unauthenticated or secondary identities.
        """
        return self.execute_probe(mission, target_url, probe)
