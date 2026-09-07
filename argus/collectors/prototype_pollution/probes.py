"""prototype_pollution: HTTP probe dispatch."""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.prototype_pollution.models import PrototypePollutionProbe, PrototypePollutionProbeResponse, PrototypePollutionVulnerabilityType

logger = logging.getLogger(__name__)


class PrototypePollutionProber:
    """
    HTTP Prober executing prototype pollution and client-side probes via
    AuthenticatedHttpClient or test mock clients with redirect tracing.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _dispatch_http(
        self,
        client: Any,
        mission: Any,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> Optional[HttpResponse]:
        """Polymorphically calls client.request across all known client signatures."""
        headers = headers or {}
        if hasattr(client, "request"):
            # Try positional with mission
            try:
                return client.request(mission, method, url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try positional without mission
            try:
                return client.request(method, url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try keyword with mission
            try:
                return client.request(mission=mission, method=method, url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try keyword without mission
            try:
                return client.request(method=method, url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass

        # Fallback to GET / POST methods
        if method.upper() == "GET" and hasattr(client, "get"):
            return client.get(url, headers=headers, params=params)
        elif method.upper() == "POST" and hasattr(client, "post"):
            return client.post(url, headers=headers, json=json_data, data=data)

        return None

    def execute_probe(
        self,
        mission: Any,
        target_url: str,
        probe: PrototypePollutionProbe,
    ) -> PrototypePollutionProbeResponse:
        """Dispatches a probe against target URL using mission HTTP client."""
        client = getattr(mission, "http_client", None)
        if client is None and hasattr(mission, "_raw_mission"):
            client = getattr(mission._raw_mission, "http_client", None)
        if client is None:
            client = AuthenticatedHttpClient(timeout=self.timeout)

        url_to_hit = probe.target_url or target_url
        headers = dict(probe.headers)
        if probe.content_type:
            headers["Content-Type"] = probe.content_type

        # Dispatch based on probe vulnerability type and technique
        if probe.vulnerability_type == PrototypePollutionVulnerabilityType.OPEN_REDIRECT:
            return self.execute_redirect_chain_probe(mission, url_to_hit, probe, max_hops=5)

        try:
            resp = self._dispatch_http(
                client=client,
                mission=mission,
                method=probe.method,
                url=url_to_hit,
                headers=headers,
                params=probe.params or None,
                json_data=probe.json_data,
                data=probe.data,
            )

            if resp is None:
                return PrototypePollutionProbeResponse(
                    probe=probe,
                    status_code=500,
                    success=False,
                    error="Empty response received from HTTP client",
                    url=url_to_hit,
                )

            status = getattr(resp, "status_code", 200) or 200
            body = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or ""
            resp_headers = dict(getattr(resp, "headers", {}))
            elapsed = getattr(resp, "elapsed", 0.05)

            # Observe potential side effects
            side_effect = False
            polluted: List[str] = []

            # Check if canary property or value is reflected in body or headers
            if probe.canary_property and (probe.canary_property in body or probe.canary_property in str(resp_headers)):
                side_effect = True
                polluted.append(probe.canary_property)
            if probe.canary_value and (probe.canary_value in body or probe.canary_value in str(resp_headers)):
                side_effect = True
                polluted.append(probe.canary_value)

            return PrototypePollutionProbeResponse(
                probe=probe,
                status_code=status,
                headers=resp_headers,
                body=body,
                elapsed=elapsed,
                success=True,
                url=url_to_hit,
                side_effect_observed=side_effect,
                polluted_properties=polluted,
            )

        except Exception as e:
            logger.debug(f"PrototypePollutionProber: Request error for {url_to_hit}: {e}")
            return PrototypePollutionProbeResponse(
                probe=probe,
                status_code=500,
                success=False,
                error=str(e),
                url=url_to_hit,
            )

    def execute_redirect_chain_probe(
        self,
        mission: Any,
        target_url: str,
        probe: PrototypePollutionProbe,
        max_hops: int = 5,
    ) -> PrototypePollutionProbeResponse:
        """
        Executes open redirect probes with multi-hop redirect chain tracing.
        Follows HTTP 3xx Location headers and meta/JS redirects up to max_hops.
        """
        client = getattr(mission, "http_client", None)
        if client is None and hasattr(mission, "_raw_mission"):
            client = getattr(mission._raw_mission, "http_client", None)
        if client is None:
            client = AuthenticatedHttpClient(timeout=self.timeout)

        current_url = target_url
        history: List[str] = [current_url]
        final_status = 200
        final_headers: Dict[str, str] = {}
        final_body = ""
        total_elapsed = 0.0

        for hop in range(max_hops):
            try:
                resp = self._dispatch_http(
                    client=client,
                    mission=mission,
                    method="GET",
                    url=current_url,
                    headers=probe.headers,
                )

                if resp is None:
                    break

                final_status = getattr(resp, "status_code", 200) or 200
                final_headers = dict(getattr(resp, "headers", {}))
                final_body = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or ""
                total_elapsed += getattr(resp, "elapsed", 0.05)

                # Check HTTP 3xx Location header (case-insensitive)
                location = None
                for hk, hv in final_headers.items():
                    if hk.lower() == "location":
                        location = hv
                        break

                # Check HTML meta refresh or JS window.location in body
                if not location and final_body:
                    meta_match = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)', final_body, re.I)
                    if meta_match:
                        location = meta_match.group(1)
                    else:
                        js_match = re.search(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']', final_body, re.I)
                        if js_match:
                            location = js_match.group(1)

                if location:
                    # Normalize next redirect URL
                    next_url = urllib.parse.urljoin(current_url, location.strip())
                    history.append(next_url)
                    current_url = next_url
                    # If redirected to external evil.com, stop trace
                    parsed_next = urllib.parse.urlparse(next_url)
                    if "evil.com" in parsed_next.netloc or "attacker.com" in parsed_next.netloc:
                        break
                else:
                    # No further redirect found
                    break

            except Exception as e:
                logger.debug(f"Redirect hop error: {e}")
                break

        return PrototypePollutionProbeResponse(
            probe=probe,
            status_code=final_status,
            headers=final_headers,
            body=final_body,
            elapsed=total_elapsed,
            success=True,
            url=current_url,
            redirect_history=history,
            side_effect_observed=len(history) > 1,
        )
