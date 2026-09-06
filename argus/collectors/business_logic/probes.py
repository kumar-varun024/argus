"""business_logic: HTTP probe dispatch."""
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from argus.http.client import AuthenticatedHttpClient
from argus.collectors.business_logic.models import BusinessLogicMutationStrategy, BusinessLogicProbe, BusinessLogicProbeResponse, BusinessLogicTechnique, WorkflowSequence

logger = logging.getLogger(__name__)


class StatefulWorkflowProber:
    """
    Executes discrete probes and multi-step workflow sequences against target endpoints.
    Maintains session state, cookie jars, extracted variables, and supports custom
    transport adapters for hermetic mock testing.
    """

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        transport_adapter: Optional[Callable[..., Any]] = None,
    ):
        self.http_client = http_client
        self.transport_adapter = transport_adapter
        self.session_variables: Dict[str, Any] = {}

    def _interpolate_value(self, val: Any, context: Dict[str, Any]) -> Any:
        """Recursively replaces template placeholders (e.g. '{cart_id}') with context variables."""
        if isinstance(val, str):
            res = val
            for k, v in context.items():
                res = res.replace(f"{{{k}}}", str(v))
            return res
        elif isinstance(val, dict):
            return {k: self._interpolate_value(v, context) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._interpolate_value(x, context) for x in val]
        return val

    def _extract_json_field(self, data: Any, path: str) -> Any:
        """Extracts nested field from dictionary using dot notation (e.g. 'data.id')."""
        if not path or data is None:
            return None
        parts = path.split(".")
        curr = data
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            elif isinstance(curr, list) and part.isdigit() and int(part) < len(curr):
                curr = curr[int(part)]
            else:
                return None
        return curr

    def execute_probe(
        self,
        probe: BusinessLogicProbe,
        session_state: Optional[Dict[str, Any]] = None,
    ) -> BusinessLogicProbeResponse:
        """
        Executes a single discrete BusinessLogicProbe using the configured transport.
        """
        ctx = dict(self.session_variables)
        if session_state:
            ctx.update(session_state)

        interpolated_url = self._interpolate_value(probe.endpoint_url, ctx)
        interpolated_json = self._interpolate_value(probe.json_data, ctx)
        interpolated_data = self._interpolate_value(probe.data, ctx)
        interpolated_params = self._interpolate_value(probe.params, ctx)

        # 1. Custom Transport Adapter (Mocking / Testing)
        if self.transport_adapter:
            try:
                res = self.transport_adapter(
                    method=probe.method,
                    url=interpolated_url,
                    headers=probe.headers,
                    json=interpolated_json,
                    data=interpolated_data,
                    params=interpolated_params,
                )
                if isinstance(res, BusinessLogicProbeResponse):
                    if not res.endpoint_url:
                        res.endpoint_url = interpolated_url
                    if not res.step_name:
                        res.step_name = probe.name
                    return res
                elif hasattr(res, "status_code"):
                    body = getattr(res, "text", "") or ""
                    json_data = None
                    try:
                        json_data = res.json() if callable(getattr(res, "json", None)) else getattr(res, "json_data", None)
                    except Exception:
                        pass
                    return BusinessLogicProbeResponse(
                        step_name=probe.name,
                        status_code=res.status_code,
                        headers=dict(getattr(res, "headers", {})),
                        body=body,
                        json_data=json_data,
                        endpoint_url=interpolated_url,
                        raw_response=res,
                    )
            except Exception as ex:
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=0,
                    error=str(ex),
                    endpoint_url=interpolated_url,
                )

        # 2. AuthenticatedHttpClient Execution
        if self.http_client:
            try:
                resp = self.http_client.send_request(
                    method=probe.method,
                    url=interpolated_url,
                    headers=probe.headers,
                    json=interpolated_json,
                    data=interpolated_data,
                    params=interpolated_params,
                )
                body = getattr(resp, "text", "") or ""
                json_data = None
                try:
                    if body:
                        json_data = json.loads(body)
                except Exception:
                    pass
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=getattr(resp, "status_code", 200),
                    headers=dict(getattr(resp, "headers", {})),
                    body=body,
                    json_data=json_data,
                    endpoint_url=interpolated_url,
                    raw_response=resp,
                )
            except Exception as ex:
                return BusinessLogicProbeResponse(
                    step_name=probe.name,
                    status_code=0,
                    error=str(ex),
                    endpoint_url=interpolated_url,
                )

        # Fallback dummy response if no client or transport configured
        return BusinessLogicProbeResponse(
            step_name=probe.name,
            status_code=200,
            body='{"status": "ok"}',
            json_data={"status": "ok"},
            endpoint_url=interpolated_url,
        )

    def execute_workflow(
        self,
        sequence: WorkflowSequence,
        session_state: Optional[Dict[str, Any]] = None,
    ) -> List[BusinessLogicProbeResponse]:
        """
        Executes a sequence of workflow steps, automatically extracting variables
        from step responses and skipping designated steps in skip_step_indices.
        """
        responses: List[BusinessLogicProbeResponse] = []
        ctx = dict(self.session_variables)
        if session_state:
            ctx.update(session_state)

        for idx, step in enumerate(sequence.steps):
            if idx in sequence.skip_step_indices:
                logger.debug("Skipping workflow step %d: %s", idx, step.name)
                continue

            probe = BusinessLogicProbe(
                name=step.name,
                endpoint_url=step.url,
                method=step.method,
                headers=step.headers,
                json_data=step.json_data,
                data=step.data,
                params=step.params,
                technique=BusinessLogicTechnique.WORKFLOW_STEP_SKIP,
                mutation_strategy=BusinessLogicMutationStrategy.OUT_OF_SEQUENCE_DISPATCH,
            )

            resp = self.execute_probe(probe, session_state=ctx)
            responses.append(resp)

            # Extract fields into context
            if step.extract_fields and resp.json_data:
                for ctx_key, json_path in step.extract_fields.items():
                    extracted_val = self._extract_json_field(resp.json_data, json_path)
                    if extracted_val is not None:
                        ctx[ctx_key] = extracted_val
                        self.session_variables[ctx_key] = extracted_val

        return responses
