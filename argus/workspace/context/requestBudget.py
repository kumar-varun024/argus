"""Admission checks for one fully prepared provider request.

The default counter charges serialized UTF-8 bytes plus a framing reserve. It
is a conservative text policy, not a provider tokenizer. Encoded media and
external context require an explicitly configured provider-aware counter.
"""

from copy import deepcopy
from dataclasses import dataclass
import json
import re
from typing import Callable, Optional

from .modelLimits import TrustedModelLimits


class RequestBudgetError(RuntimeError):
    """Safe, count-only failure; provider payloads and callback errors stay private."""

    _MESSAGES = {
        "invalid_configuration": "Invalid provider budget configuration.",
        "invalid_output_budget": "Invalid output token budget.",
        "invalid_payload": "Provider request cannot be measured.",
        "unmeasured_content": "This provider cannot measure the attached or external content.",
        "counter_failed": "Provider prompt measurement failed.",
        "invalid_measurement": "Provider prompt measurement is invalid.",
        "invalid_stream_usage": "Provider stream usage could not be verified.",
        "invalid_completion_usage": "Provider completion usage could not be verified.",
        "context_budget_exceeded": "Provider request exceeds the configured context budget.",
        "model_binding_mismatch": "Provider request does not match the configured model binding.",
        "model_input_limit_exceeded": "Provider request exceeds the configured model input limit.",
        "model_output_limit_exceeded": "Provider request exceeds the configured model output limit.",
    }

    def __init__(self, reason: str):
        self.reason = reason if type(reason) is str and reason in self._MESSAGES else "counter_failed"
        super().__init__(self._MESSAGES[self.reason])


@dataclass(frozen=True)
class RequestBudgetResult:
    input_tokens: int
    output_tokens: int
    framing_tokens: int
    capacity_tokens: int
    counter_kind: str
    counter_name: str


def _has_nontext_context(value):
    if isinstance(value, dict):
        if any(key in value for key in (
            "image_url", "input_audio", "inline_data", "inlineData", "file_data", "fileData",
            "cached_content", "cachedContent", "file_id", "audio_url", "video_url",
            "attachments",
        )):
            return True
        if value.get("type") in {
            "image", "image_url", "input_image", "output_image", "audio", "input_audio",
            "output_audio", "audio_url", "video", "input_video", "video_url",
            "file", "input_file", "output_file", "document",
        }:
            return True
        return any(_has_nontext_context(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_nontext_context(item) for item in value)
    return False


@dataclass(frozen=True, kw_only=True)
class ProviderRequestBudget:
    """Application context ceiling, output reserve and bound request counter.

    A custom callback must count the complete provider input for the selected
    model, including its template, schemas and any media it claims to support.
    Counts cover input only; output and framing reserves are added here. The
    callback sees a private copy of the prepared body, never authentication.
    """

    capacity_tokens: int = 16384
    default_output_tokens: int = 4096
    framing_tokens: int = 512
    prompt_counter: Optional[Callable[[dict], int]] = None
    supports_multimodal: bool = False
    counter_name: str = ""
    model_limits: Optional[TrustedModelLimits] = None

    def __post_init__(self):
        if (type(self.capacity_tokens) is not int or self.capacity_tokens < 1
                or type(self.default_output_tokens) is not int or self.default_output_tokens < 1
                or type(self.framing_tokens) is not int or self.framing_tokens < 0
                or self.default_output_tokens + self.framing_tokens >= self.capacity_tokens
                or type(self.supports_multimodal) is not bool
                or (self.prompt_counter is not None and not callable(self.prompt_counter))
                or (self.supports_multimodal and self.prompt_counter is None)
                or type(self.counter_name) is not str
                or (self.model_limits is not None and type(self.model_limits) is not TrustedModelLimits)
                or (self.counter_name and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.counter_name))):
            raise RequestBudgetError("invalid_configuration")
        if (self.default_output_tokens + self.framing_tokens >= self.effective_capacity_tokens
                or (self.model_limits is not None
                    and self.default_output_tokens > self.model_limits.output_tokens)):
            raise RequestBudgetError("invalid_configuration")

    @property
    def effective_capacity_tokens(self) -> int:
        return min(self.capacity_tokens, self.model_limits.context_tokens) if self.model_limits else self.capacity_tokens

    def input_allowance(self, output_tokens: int) -> int:
        self.output_limit({"max_tokens": output_tokens})
        remaining = self.effective_capacity_tokens - output_tokens - self.framing_tokens
        return min(remaining, self.model_limits.input_tokens) if self.model_limits else remaining

    def validate_binding(self, provider: str, model: str, api_base: str) -> None:
        if self.model_limits is not None:
            self.model_limits.validate_binding(provider, model, api_base)
        try:
            validator = getattr(self.prompt_counter, "validate_binding", None)
            if validator is not None:
                validator(provider, model, api_base)
        except Exception:
            raise RequestBudgetError("model_binding_mismatch") from None

    def output_limit(self, kwargs: dict) -> int:
        output = kwargs.get("max_tokens", self.default_output_tokens)
        if type(output) is not int or output < 1:
            raise RequestBudgetError("invalid_output_budget")
        if self.model_limits is not None and output > self.model_limits.output_tokens:
            raise RequestBudgetError("model_output_limit_exceeded")
        if output + self.framing_tokens >= self.effective_capacity_tokens:
            raise RequestBudgetError("context_budget_exceeded")
        return output

    def measure(self, payload: dict) -> int:
        """Count a candidate even when it needs older-history compaction."""
        try:
            if not isinstance(payload, dict):
                raise TypeError
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
            nontext = _has_nontext_context(payload)
        except (TypeError, ValueError, RecursionError, UnicodeError):
            raise RequestBudgetError("invalid_payload") from None
        if nontext and not self.supports_multimodal:
            raise RequestBudgetError("unmeasured_content")

        if self.prompt_counter is None:
            measured = len(encoded)
        else:
            try:
                measured = self.prompt_counter(deepcopy(payload))
            except Exception:
                raise RequestBudgetError("counter_failed") from None
        if type(measured) is not int or measured < 0:
            raise RequestBudgetError("invalid_measurement")
        return measured

    def check(self, payload: dict, output_tokens: int) -> RequestBudgetResult:
        self.output_limit({"max_tokens": output_tokens})
        measured = self.measure(payload)
        if self.model_limits is not None and measured > self.model_limits.input_tokens:
            raise RequestBudgetError("model_input_limit_exceeded")
        if measured + output_tokens + self.framing_tokens > self.effective_capacity_tokens:
            raise RequestBudgetError("context_budget_exceeded")
        return RequestBudgetResult(
            input_tokens=measured, output_tokens=output_tokens,
            framing_tokens=self.framing_tokens, capacity_tokens=self.effective_capacity_tokens,
            counter_kind="provider_counter" if self.prompt_counter is not None else "conservative_text_bytes",
            counter_name=self.counter_name or ("provider_counter" if self.prompt_counter is not None else "utf8_json_bytes"),
        )
