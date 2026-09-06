"""SSTI HTTP probe dispatch across parameter locations."""
from __future__ import annotations

import copy
import time
import urllib.parse
from typing import Any, Dict, Optional

from argus.collectors.ssti.models import SSTIProbe, SSTIProbeResponse


class SSTIProber:
    """
    Executes SSTI probes across GET query parameters, POST form & JSON bodies,
    path segments, and HTTP request headers.
    """

    def __init__(self, http_client: Optional[Any] = None) -> None:
        self.http_client = http_client

    def measure_baseline(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> SSTIProbeResponse:
        """
        Takes a baseline measurement of the target endpoint prior to injection.
        """
        probe = SSTIProbe(url=url, method=method, headers=headers or {})
        return self.execute_probe(probe)

    def execute_probe(self, probe: SSTIProbe) -> SSTIProbeResponse:
        """
        Dispatches an HTTP request with the probe injected into the designated parameter location.
        """
        if self.http_client is None:
            return SSTIProbeResponse(probe=probe, status_code=200, body="", elapsed=0.05)

        target_url = probe.url
        method = probe.method.upper()
        req_headers = dict(probe.headers)
        data = copy.deepcopy(probe.data) if probe.data is not None else None
        json_body = copy.deepcopy(probe.json_body) if probe.json_body is not None else None

        # Inject payload based on parameter type
        if probe.parameter_type == "query":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            param_key = probe.parameter or "q"
            qs[param_key] = [probe.payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            target_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))

        elif probe.parameter_type == "body":
            if data is None:
                data = {}
            param_key = probe.parameter or "template"
            data[param_key] = probe.payload
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        elif probe.parameter_type == "json":
            param_key = probe.parameter or "template"
            if json_body is None:
                json_body = {}
            if isinstance(json_body, dict):
                json_body[param_key] = probe.payload
            req_headers.setdefault("Content-Type", "application/json")

        elif probe.parameter_type == "header":
            header_key = probe.parameter or "X-Template"
            req_headers[header_key] = probe.payload

        elif probe.parameter_type == "path":
            parsed = urllib.parse.urlparse(target_url)
            parts = parsed.path.strip("/").split("/")
            if parts and parts[-1]:
                parts[-1] = urllib.parse.quote(probe.payload, safe="")
            else:
                parts = [urllib.parse.quote(probe.payload, safe="")]
            new_path = "/" + "/".join(parts)
            target_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))

        start_time = time.time()
        try:
            if method == "POST":
                # Handle json vs data
                if json_body is not None:
                    resp = self.http_client.post(
                        target_url,
                        json=json_body,
                        headers=req_headers,
                        timeout=probe.timeout,
                    )
                else:
                    resp = self.http_client.post(
                        target_url,
                        data=data,
                        headers=req_headers,
                        timeout=probe.timeout,
                    )
            else:
                resp = self.http_client.get(
                    target_url,
                    headers=req_headers,
                    timeout=probe.timeout,
                )
            calc_elapsed = time.time() - start_time
            resp_elapsed = getattr(resp, "elapsed", None)
            if resp_elapsed is not None and isinstance(resp_elapsed, (int, float)) and resp_elapsed > 0:
                elapsed = float(resp_elapsed)
            else:
                elapsed = calc_elapsed

            body_content = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or getattr(resp, "text", "") or ""
            status_code = getattr(resp, "status_code", 200)
            headers_dict = dict(getattr(resp, "headers", {}))
            success = bool(getattr(resp, "success", 200 <= status_code < 400))

            return SSTIProbeResponse(
                probe=probe,
                status_code=status_code,
                body=str(body_content),
                headers=headers_dict,
                elapsed=elapsed,
                success=success,
                raw_response=resp,
            )

        except Exception as e:
            logger.debug("SSTI probe execution failed against %s: %s", target_url, e)
            calc_elapsed = time.time() - start_time
            return SSTIProbeResponse(
                probe=probe,
                status_code=500,
                body="",
                elapsed=calc_elapsed,
                success=False,
            )


# =============================================================================
# SSTI Collector (BaseCollector Implementation)
# =============================================================================

