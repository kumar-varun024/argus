"""Operator-pinned limits for one exact provider, model and endpoint."""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit


def _normalized_base(value: str) -> str:
    if (type(value) is not str or not value
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or "?" in value or "#" in value or "\\" in value):
        raise ValueError
    # Accessing port also rejects malformed or out-of-range ports.
    parsed.port
    return value.rstrip("/")


@dataclass(frozen=True, kw_only=True)
class TrustedModelLimits:
    """Pinned capacity; discovery metadata cannot widen these limits."""

    provider: str
    model: str
    api_base: str
    context_tokens: int
    input_tokens: int
    output_tokens: int
    provenance: str = "operator"

    def __post_init__(self):
        from .requestBudget import RequestBudgetError

        try:
            if (any(type(value) is not str or not value or value.strip() != value
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    for value in (self.provider, self.model))
                    or any(type(value) is not int or value < 1
                           for value in (self.context_tokens, self.input_tokens, self.output_tokens))
                    or self.input_tokens > self.context_tokens
                    or self.output_tokens > self.context_tokens
                    or type(self.provenance) is not str
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.provenance)):
                raise ValueError
            normalized = _normalized_base(self.api_base)
        except (TypeError, ValueError):
            raise RequestBudgetError("invalid_configuration") from None
        object.__setattr__(self, "api_base", normalized)

    def validate_binding(self, provider: str, model: str, api_base: str) -> None:
        from .requestBudget import RequestBudgetError

        try:
            matches = (type(provider) is str and type(model) is str
                       and provider == self.provider and model == self.model
                       and _normalized_base(api_base) == self.api_base)
        except (TypeError, ValueError):
            matches = False
        if not matches:
            raise RequestBudgetError("model_binding_mismatch") from None
