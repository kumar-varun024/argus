"""Admission covers fixed authority, wire text, output reserve and opaque media."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
import json

import pytest

from argus.workspace.context.requestBudget import ProviderRequestBudget, RequestBudgetError
from argus.workspace.context.modelLimits import TrustedModelLimits


def test_whole_body_text_cost_and_exact_boundary():
    body = {"model": "model", "messages": [{"role": "system", "content": "守る"},
                                             {"role": "user", "content": "latest"}],
            "tools": [{"name": "read", "description": "preserve schema"}], "max_tokens": 10}
    size = len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())
    budget = ProviderRequestBudget(capacity_tokens=size + 10 + 5, default_output_tokens=10, framing_tokens=5)
    result = budget.check(body, 10)
    assert result.input_tokens == size
    assert result.counter_kind == "conservative_text_bytes"
    assert result.output_tokens + result.framing_tokens + result.input_tokens == result.capacity_tokens
    with pytest.raises(RequestBudgetError, match="exceeds"):
        budget.check({**body, "extra": "x"}, 10)


def test_custom_counter_receives_all_authority_and_cannot_modify_body():
    body = {"model": "model", "messages": [{"role": "system", "content": "policy"},
                                             {"role": "user", "content": "latest"}],
            "tools": [{"function": {"name": "read", "parameters": {"required": ["id"]}}}]}
    original = deepcopy(body)
    seen = []
    def counter(candidate):
        seen.append(deepcopy(candidate))
        candidate["messages"][0]["content"] = "changed"
        candidate["tools"].clear()
        return 50
    budget = ProviderRequestBudget(capacity_tokens=100, default_output_tokens=40, framing_tokens=10,
                                   prompt_counter=counter, counter_name="bound_model_counter")
    result = budget.check(body, 40)
    assert seen == [original] and body == original
    assert result.input_tokens == 50 and result.counter_kind == "provider_counter"
    assert result.counter_name == "bound_model_counter"
    assert "policy" not in repr(result) and "latest" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.input_tokens = 0
    with pytest.raises(FrozenInstanceError):
        budget.capacity_tokens = 1000


@pytest.mark.parametrize("options", [
    {"capacity_tokens": True}, {"capacity_tokens": 0}, {"capacity_tokens": 10},
    {"default_output_tokens": False}, {"default_output_tokens": 0},
    {"framing_tokens": -1}, {"framing_tokens": True},
    {"prompt_counter": 3}, {"supports_multimodal": 1},
    {"supports_multimodal": True}, {"counter_name": "secret with spaces"},
])
def test_bad_configuration_refuses(options):
    with pytest.raises(RequestBudgetError) as error:
        ProviderRequestBudget(**options)
    assert error.value.reason == "invalid_configuration"


@pytest.mark.parametrize("value", [None, True, 0, -2, 2.5, "12"])
def test_explicit_invalid_output_does_not_default(value):
    budget = ProviderRequestBudget()
    with pytest.raises(RequestBudgetError):
        budget.output_limit({"max_tokens": value})
    assert budget.output_limit({}) == 4096


@pytest.mark.parametrize("value", [True, None, -1, 0.5, "10"])
def test_bad_counter_result_refuses(value):
    budget = ProviderRequestBudget(prompt_counter=lambda body: value)
    with pytest.raises(RequestBudgetError) as error:
        budget.check({"messages": []}, 4096)
    assert error.value.reason == "invalid_measurement"


@pytest.mark.parametrize("media", [
    {"type": "image_url", "image_url": {"url": "data:image/png;base64,c2VjcmV0"}},
    {"inline_data": {"mime_type": "image/png", "data": "c2VjcmV0"}},
    {"inlineData": {"mimeType": "audio/wav", "data": "c2VjcmV0"}},
    {"file_data": {"file_uri": "gs://private"}},
    {"cachedContent": "cachedContents/private"},
])
def test_opaque_context_requires_explicit_counter_support(media):
    body = {"contents": [{"parts": [media]}]}
    calls = []
    def counter(payload):
        calls.append(payload)
        return 500
    for budget in (ProviderRequestBudget(), ProviderRequestBudget(prompt_counter=counter)):
        with pytest.raises(RequestBudgetError) as error:
            budget.check(body, 4096)
        assert error.value.reason == "unmeasured_content"
    assert not calls
    result = ProviderRequestBudget(prompt_counter=counter, supports_multimodal=True).check(body, 4096)
    assert result.input_tokens == 500 and calls == [body]


def test_failing_counter_and_untrusted_reason_do_not_echo_private_data():
    def counter(body):
        raise RuntimeError("secret-token raw-policy raw-image")
    with pytest.raises(RequestBudgetError) as error:
        ProviderRequestBudget(prompt_counter=counter).check({"messages": ["raw-policy"]}, 4096)
    assert error.value.reason == "counter_failed"
    assert error.value.__suppress_context__
    assert "raw-policy" not in str(error.value) and "secret-token" not in str(error.value)
    assert RequestBudgetError("secret-token").reason == "counter_failed"
    assert RequestBudgetError([]).reason == "counter_failed"
    assert set(asdict(ProviderRequestBudget().check({}, 4096))) == {
        "input_tokens", "output_tokens", "framing_tokens", "capacity_tokens", "counter_kind", "counter_name"}


@pytest.mark.parametrize("body", [["not-an-object"], {"invalid": object()}, {"nan": float("nan")}, {"type": []}])
def test_unmeasurable_payload_refuses_before_counter(body):
    called = []
    with pytest.raises(RequestBudgetError) as error:
        ProviderRequestBudget(prompt_counter=lambda data: called.append(data)).check(body, 4096)
    assert error.value.reason == "invalid_payload"
    assert not called


def pinned_budget(*, context=100, input_limit=80, output_limit=30, capacity=120, counter=None):
    return ProviderRequestBudget(
        capacity_tokens=capacity, default_output_tokens=20, framing_tokens=10,
        model_limits=TrustedModelLimits(provider="openai-compatible", model="exact-model",
            api_base="https://inference.example/v1", context_tokens=context,
            input_tokens=input_limit, output_tokens=output_limit),
        prompt_counter=counter or (lambda body: body["measured"]),
    )


def test_pinned_context_and_application_capacity_each_narrow_admission():
    for budget in (pinned_budget(), pinned_budget(context=120, capacity=100)):
        assert budget.effective_capacity_tokens == 100
        assert budget.input_allowance(20) == 70
        assert budget.check({"measured": 70}, 20).capacity_tokens == 100
        with pytest.raises(RequestBudgetError) as error:
            budget.check({"measured": 71}, 20)
        assert error.value.reason == "context_budget_exceeded"


def test_independent_pinned_input_and_output_limits():
    budget = pinned_budget(input_limit=50)
    assert budget.input_allowance(20) == 50
    assert budget.check({"measured": 50}, 30).input_tokens == 50
    with pytest.raises(RequestBudgetError) as error:
        budget.check({"measured": 51}, 20)
    assert error.value.reason == "model_input_limit_exceeded"
    with pytest.raises(RequestBudgetError) as error:
        budget.output_limit({"max_tokens": 31})
    assert error.value.reason == "model_output_limit_exceeded"


@pytest.mark.parametrize("options", [
    {"model_limits": {}},
    {"default_output_tokens": 31},
    {"framing_tokens": 80},
])
def test_invalid_pinned_budget_configuration_refuses(options):
    from dataclasses import replace
    with pytest.raises(RequestBudgetError) as error:
        replace(pinned_budget(), **options)
    assert error.value.reason == "invalid_configuration"


def test_budget_validates_limits_and_bound_counter_identity():
    class BoundCounter:
        def __call__(self, body):
            return 1

        def validate_binding(self, provider, model, api_base):
            if model != "counter-model":
                raise ValueError("private-counter-detail")

    budget = pinned_budget()
    budget.validate_binding("openai-compatible", "exact-model", "https://inference.example/v1/")
    with pytest.raises(RequestBudgetError) as error:
        budget.validate_binding("openai-compatible", "alias", "https://inference.example/v1")
    assert error.value.reason == "model_binding_mismatch"
    callback_budget = ProviderRequestBudget(prompt_counter=BoundCounter())
    callback_budget.validate_binding("openai-compatible", "counter-model", "https://inference.example/v1")
    with pytest.raises(RequestBudgetError) as error:
        callback_budget.validate_binding("openai-compatible", "exact-model", "https://inference.example/v1")
    assert error.value.reason == "model_binding_mismatch"
    assert "private-counter-detail" not in str(error.value)
    with pytest.raises(RequestBudgetError) as error:
        pinned_budget(counter=BoundCounter()).validate_binding(
            "openai-compatible", "exact-model", "https://inference.example/v1")
    assert error.value.reason == "model_binding_mismatch"


def test_counter_binding_descriptor_errors_stay_private():
    class BrokenBinding:
        def __call__(self, body):
            return 1

        @property
        def validate_binding(self):
            raise RuntimeError("private-counter-detail")

    with pytest.raises(RequestBudgetError) as error:
        ProviderRequestBudget(prompt_counter=BrokenBinding()).validate_binding(
            "openai-compatible", "model", "https://inference.example/v1")
    assert error.value.reason == "model_binding_mismatch"
    assert "private-counter-detail" not in str(error.value)
