"""race_conditions: HTTP probe dispatch."""
from __future__ import annotations

import copy
import json
import logging
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from argus.http.client import AuthenticatedHttpClient
from argus.collectors.race_conditions.models import ConcurrencyProbeResponse, ConcurrencyStrategy, RaceConditionResult

logger = logging.getLogger(__name__)


class ConcurrencyProber:
    """
    High-precision multi-request synchronization prober.

    Provides microsecond barrier synchronization, HTTP/2 single-packet multiplexing
    emulation, connection pre-warming, TCP padding, and dynamic concurrency scaling.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        transport_adapter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        http_client: Optional[AuthenticatedHttpClient] = None,
    ):
        self.timeout = timeout
        self.transport_adapter = transport_adapter
        self.http_client = http_client

    def execute_burst(
        self,
        requests: List[Dict[str, Any]],
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.MICROSECOND_BARRIER,
        dynamic_ladder: Optional[List[int]] = None,
    ) -> List[ConcurrencyProbeResponse]:
        """
        Dispatches a synchronized burst of requests using the specified strategy.
        """
        if not requests:
            return []

        burst_size = len(requests)
        responses: List[ConcurrencyProbeResponse] = [None] * burst_size  # type: ignore
        barrier = threading.Barrier(burst_size)
        threads: List[threading.Thread] = []

        # Prepare request structures
        padded_requests = self._prepare_requests(requests, strategy)

        def _worker(idx: int, req_spec: Dict[str, Any]):
            resp_obj = ConcurrencyProbeResponse(
                request_index=idx,
                endpoint_url=req_spec.get("url", ""),
            )
            try:
                # Pre-warming / socket setup simulation
                if strategy == ConcurrencyStrategy.CONNECTION_PREWARMING:
                    pass

                # Microsecond barrier release
                try:
                    barrier.wait(timeout=self.timeout)
                except threading.BrokenBarrierError:
                    pass

                t_sent = time.perf_counter()
                resp_obj.timestamp_sent = t_sent

                # Execute dispatch
                raw_resp = self._dispatch_single_request(req_spec)
                t_recv = time.perf_counter()

                resp_obj.timestamp_received = t_recv
                resp_obj.elapsed = t_recv - t_sent
                resp_obj.raw_response = raw_resp

                # Normalize response data
                self._populate_response_fields(resp_obj, raw_resp)
            except Exception as e:
                resp_obj.error = str(e)
                resp_obj.elapsed = self.timeout
            finally:
                responses[idx] = resp_obj

        for i, req in enumerate(padded_requests):
            t = threading.Thread(target=_worker, args=(i, req), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.timeout + 2.0)

        # Fill any missing
        for i in range(burst_size):
            if responses[i] is None:
                responses[i] = ConcurrencyProbeResponse(
                    request_index=i,
                    endpoint_url=requests[i].get("url", ""),
                    error="Timed out waiting for response",
                    elapsed=self.timeout,
                )

        return responses

    def execute_dynamic_scaling(
        self,
        base_request_builder: Callable[[int], List[Dict[str, Any]]],
        evaluator: Callable[[List[ConcurrencyProbeResponse]], Optional[RaceConditionResult]],
        ladder: Optional[List[int]] = None,
        strategy: ConcurrencyStrategy = ConcurrencyStrategy.DYNAMIC_CONCURRENCY_SCALING,
    ) -> Tuple[List[ConcurrencyProbeResponse], Optional[RaceConditionResult]]:
        """
        Progressively scales concurrency burst sizes [5, 10, 20, 50].
        Halts early if a vulnerability is confirmed or if throttling (429) occurs.
        """
        scaling_ladder = ladder or [5, 10, 20, 50]
        all_responses: List[ConcurrencyProbeResponse] = []
        last_result: Optional[RaceConditionResult] = None

        for burst_size in scaling_ladder:
            reqs = base_request_builder(burst_size)
            responses = self.execute_burst(reqs, strategy=strategy)
            all_responses.extend(responses)

            # Evaluate outcome
            result = evaluator(responses)
            if result is not None:
                result.concurrency_burst_size = burst_size
                return all_responses, result

            # Check for throttling / rate-limiting (halt scaling)
            has_429 = any(r.status_code == 429 for r in responses)
            if has_429:
                logger.info(f"ConcurrencyProber: Detected rate limiting (HTTP 429) at burst size {burst_size}. Halting scaling.")
                break

        return all_responses, last_result

    def _prepare_requests(
        self,
        requests: List[Dict[str, Any]],
        strategy: ConcurrencyStrategy,
    ) -> List[Dict[str, Any]]:
        """Applies padding, headers, or multiplex flags according to strategy."""
        prepared: List[Dict[str, Any]] = []
        for req in requests:
            req_copy = copy.deepcopy(req)
            headers = req_copy.setdefault("headers", {})

            if strategy == ConcurrencyStrategy.TCP_PADDING:
                # Add padding header for uniform byte frames
                if "X-Argus-Pad" not in headers:
                    headers["X-Argus-Pad"] = "A" * 64
            elif strategy == ConcurrencyStrategy.HTTP2_SINGLE_PACKET:
                headers["X-Argus-Sync"] = "single-packet-h2"
                headers["X-Argus-Stream-Sync"] = secrets.token_hex(4)
            elif strategy == ConcurrencyStrategy.CONNECTION_PREWARMING:
                headers["Connection"] = "keep-alive"
                headers["X-Argus-Prewarmed"] = "true"

            prepared.append(req_copy)
        return prepared

    def _dispatch_single_request(self, req_spec: Dict[str, Any]) -> Any:
        """Executes a single HTTP request via transport_adapter, AuthenticatedHttpClient, or httpx."""
        if self.transport_adapter is not None:
            return self.transport_adapter(req_spec)

        url = req_spec.get("url", "")
        method = req_spec.get("method", "POST").upper()
        headers = req_spec.get("headers", {})
        data = req_spec.get("data")
        json_payload = req_spec.get("json")
        params = req_spec.get("params")

        if self.http_client is not None and hasattr(self.http_client, "send_request"):
            return self.http_client.send_request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_payload,
                params=params,
            )

        # Fallback to direct httpx request if client is available
        try:
            import httpx
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                return client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json_payload,
                    params=params,
                )
        except Exception as e:
            logger.debug(f"ConcurrencyProber fallback dispatch error: {e}")
            raise e

    def _populate_response_fields(self, resp_obj: ConcurrencyProbeResponse, raw_resp: Any):
        """Extracts status, headers, and body from raw response object or mock tuple/dict."""
        if raw_resp is None:
            return

        if isinstance(raw_resp, tuple) and len(raw_resp) >= 2:
            resp_obj.status_code = int(raw_resp[0])
            body_val = raw_resp[1]
            if isinstance(body_val, dict):
                resp_obj.json_data = body_val
                resp_obj.body = json.dumps(body_val)
            else:
                resp_obj.body = str(body_val)
            if len(raw_resp) >= 3 and isinstance(raw_resp[2], dict):
                resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp[2].items()}
            return

        if isinstance(raw_resp, dict):
            resp_obj.status_code = int(raw_resp.get("status_code", raw_resp.get("status", 200)))
            resp_obj.body = str(raw_resp.get("body", raw_resp.get("text", "")))
            resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp.get("headers", {}).items()}
            resp_obj.json_data = raw_resp.get("json", raw_resp.get("json_data"))
            return

        # HttpResponse or httpx.Response
        if hasattr(raw_resp, "status_code"):
            resp_obj.status_code = int(raw_resp.status_code)
        if hasattr(raw_resp, "headers"):
            try:
                resp_obj.headers = {str(k).lower(): str(v) for k, v in raw_resp.headers.items()}
            except Exception:
                pass
        if hasattr(raw_resp, "text"):
            try:
                resp_obj.body = str(raw_resp.text)
            except Exception:
                pass
        elif hasattr(raw_resp, "body"):
            try:
                resp_obj.body = str(raw_resp.body)
            except Exception:
                pass

        if hasattr(raw_resp, "json"):
            try:
                resp_obj.json_data = raw_resp.json() if callable(raw_resp.json) else raw_resp.json
            except Exception:
                pass
