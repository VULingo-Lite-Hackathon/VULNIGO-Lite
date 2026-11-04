import json

import httpx
import pytest
from pydantic import BaseModel

from agents.config import Settings
from agents.inference import (
    BudgetExhausted,
    MODEL_FAILURES,
    ModelSubstitution,
    Inference,
    ModelUnavailable,
    UnvalidatedOutput,
    extract_json,
)


class Ping(BaseModel):
    ok: bool
    note: str
    mode: str = "ping"


def completion(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        },
    )


def settings(**overrides) -> Settings:
    base = {
        "base_url": "https://infer.example.test/v1",
        "api_key": "secret-key-abc",
        "models": {"red": "model-a"},
        "max_calls": 10,
        "max_total_tokens": 100000,
    }
    base.update(overrides)
    return Settings(**base)


def client_for(handler) -> Inference:
    return Inference(settings(), client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_json_survives_code_fence_and_prose():
    payload = extract_json('Sure!\n```json\n{"ok": true, "note": "hi", "mode": "ping"}\n```\nDone.')
    assert payload == {"ok": True, "note": "hi", "mode": "ping"}


def test_valid_reply_is_returned_as_an_object_and_charged_once():
    client = client_for(lambda request: completion('{"ok": true, "note": "hi"}'))
    answer, usage = client.ask("red", "sys", "user", Ping)
    assert answer.ok is True
    assert usage.total == 18
    assert client.budget.calls == 1


def test_malformed_output_is_repaired_then_raises_instead_of_guessing():
    seen = []

    def handler(request):
        seen.append(json.loads(request.content)["messages"])
        return completion("I think the repo is probably fine")

    client = client_for(handler)
    with pytest.raises(UnvalidatedOutput) as caught:
        client.ask("red", "sys", "user", Ping)

    assert len(seen) == 3, "two repair attempts, then it stops"
    assert "could not be used" in seen[-1][-1]["content"]
    assert caught.value.raw_preview.startswith("I think")
    assert client.budget.calls == 3


def test_http_error_redacts_the_key():
    def handler(request):
        return httpx.Response(401, text=f"bad token {request.headers['Authorization']}")

    client = client_for(handler)
    with pytest.raises(ModelUnavailable) as caught:
        client.ask("red", "sys", "user", Ping)
    assert "secret-key-abc" not in str(caught.value)


def test_call_budget_stops_before_the_request():
    calls = []

    def handler(request):
        calls.append(request)
        return completion('{"ok": true, "note": "hi"}')

    client = Inference(
        settings(max_calls=1), client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    client.ask("red", "sys", "user", Ping)
    with pytest.raises(BudgetExhausted):
        client.ask("red", "sys", "user", Ping)
    assert len(calls) == 1


def test_unknown_role_model_is_a_config_error_not_a_silent_default():
    client = client_for(lambda request: completion("{}"))
    from agents.config import ConfigError

    with pytest.raises(ConfigError):
        client.ask("manager", "sys", "user", Ping)


def test_a_silently_substituted_model_is_an_error_not_a_quiet_downgrade():
    """The endpoint documents that an unknown model id falls back to a flash variant.

    That would let the report name a model we never actually ran, so the client refuses it.
    """
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"ok": true, "note": "hi"}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                "model": "some-cheap-flash-variant",
            },
        )

    client = client_for(handler)
    with pytest.raises(ModelSubstitution) as caught:
        client.ask("red", "sys", "user", Ping)
    assert "some-cheap-flash-variant" in str(caught.value) and "model-a" in str(caught.value)


def test_a_matching_model_name_is_accepted_and_recorded():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "model-a",
                "choices": [{"message": {"content": '{"ok": true, "note": "hi"}'}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 5},
            },
        )

    client = client_for(handler)
    answer, usage = client.ask("red", "sys", "user", Ping)
    assert answer.ok is True and usage.requested_model == "model-a"


def test_a_response_without_a_model_field_is_not_treated_as_a_substitution():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"ok": true, "note": "hi"}'}}]},
        )

    client = client_for(handler)
    assert client.ask("red", "sys", "user", Ping)[0].ok is True


def test_a_long_error_body_is_redacted_before_it_is_truncated():
    key = "secret-key-abc"

    def handler(request):
        return httpx.Response(401, text=("x" * 500) + key)

    client = client_for(handler)
    with pytest.raises(ModelUnavailable) as caught:
        client.ask("red", "sys", "user", Ping)
    assert key not in str(caught.value)



def test_model_failures_are_one_catchable_family():
    from agents.inference import MODEL_FAILURES

    assert set(MODEL_FAILURES) == {
        ModelUnavailable,
        ModelSubstitution,
        UnvalidatedOutput,
        BudgetExhausted,
    }


@pytest.mark.parametrize("offset", [0, 400])
def test_the_key_is_redacted_whether_it_is_early_or_late_in_the_body(offset):
    """Both positions matter: redacting after truncating only looks safe for late keys."""
    key = "secret-key-abc"
    body = ("x" * offset) + key + ("y" * 600)

    client = client_for(lambda request: httpx.Response(401, text=body))
    with pytest.raises(ModelUnavailable) as caught:
        client.ask("red", "sys", "user", Ping)
    assert key not in str(caught.value)
    assert "401" in str(caught.value)


def test_a_200_response_that_is_not_json_is_a_recorded_model_failure():
    def handler(request):
        return httpx.Response(200, text="<html>gateway timeout</html>")

    client = client_for(handler)
    with pytest.raises(ModelUnavailable, match="non-JSON"):
        client.ask("red", "sys", "user", Ping)


def test_a_pointer_survives_a_non_json_response_without_crashing_the_caller():
    from agents.manager import ManagerAgent
    from agents.demo_run import CannedModel

    class BadJson:
        def __init__(self):
            self.budget = None

        def ask(self, *args, **kwargs):
            raise ModelUnavailable("endpoint returned non-JSON (JSONDecodeError)")

    manager = ManagerAgent(BadJson())
    result = manager.pointer("ptr-attack", "attack: something happened", ["run-1"])
    assert result.pointer is None and "model failed" in result.reason
