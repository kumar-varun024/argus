"""Limits bind to explicit operator identities, never inferred model aliases."""

from dataclasses import FrozenInstanceError

import pytest

from argus.workspace.context.modelLimits import TrustedModelLimits
from argus.workspace.context.requestBudget import RequestBudgetError


def limits(**changes):
    return TrustedModelLimits(**{
        "provider": "openai-compatible", "model": "exact-model",
        "api_base": "https://inference.example/v1/", "context_tokens": 100,
        "input_tokens": 80, "output_tokens": 20, **changes,
    })


def test_exact_binding_and_immutable_operator_labels():
    pinned = limits()
    assert pinned.api_base == "https://inference.example/v1"
    assert pinned.provenance == "operator"
    pinned.validate_binding("openai-compatible", "exact-model", "https://inference.example/v1///")
    for field, value in (("model", "alias"), ("context_tokens", 10000), ("provenance", "discovery")):
        with pytest.raises(FrozenInstanceError):
            setattr(pinned, field, value)


@pytest.mark.parametrize("changes", [
    {"provider": "gemini"}, {"model": "exact-model:latest"}, {"model": "Exact-model"},
    {"api_base": "https://other.example/v1"}, {"api_base": "https://inference.example/v2"},
    {"api_base": "https://INFERENCE.example/v1"}, {"api_base": "http://inference.example/v1"},
    {"api_base": "https://user:secret@inference.example/v1"},
    {"api_base": "https://inference.example/v1?secret=value"}, {"api_base": None},
])
def test_mismatched_identity_refuses_without_echo(changes):
    with pytest.raises(RequestBudgetError) as error:
        limits().validate_binding(**{
            "provider": "openai-compatible", "model": "exact-model",
            "api_base": "https://inference.example/v1", **changes,
        })
    assert error.value.reason == "model_binding_mismatch"
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("changes", [
    {"context_tokens": True}, {"input_tokens": False}, {"output_tokens": 1.5},
    {"context_tokens": 0}, {"input_tokens": -1}, {"output_tokens": "20"},
    {"input_tokens": 101}, {"output_tokens": 101},
    {"provider": ""}, {"model": "exact-model\n"}, {"model": None},
    {"provenance": "secret with spaces"}, {"provenance": "x" * 65}, {"provenance": None},
    {"api_base": "file:///model"}, {"api_base": "https:///v1"},
    {"api_base": "https://user:secret@inference.example/v1"},
    {"api_base": "https://inference.example/v1?"},
    {"api_base": "https://inference.example/v1#"},
    {"api_base": "https://inference.example:999999/v1"},
    {"api_base": "https://inference.example/\n"},
])
def test_invalid_limits_fail_closed(changes):
    with pytest.raises(RequestBudgetError) as error:
        limits(**changes)
    assert error.value.reason == "invalid_configuration"
    assert "secret" not in str(error.value)
