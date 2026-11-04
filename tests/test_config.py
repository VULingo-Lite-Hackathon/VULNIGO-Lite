import pytest

from agents.config import ConfigError, load


def set_env(monkeypatch, **values):
    for key in (
        "VULNIGO_INFERENCE_BASE_URL",
        "VULNIGO_INFERENCE_API_KEY",
        "VULNIGO_MODEL_RED",
        "VULNIGO_MODEL_BLUE",
        "VULNIGO_MODEL_MANAGER",
        "VULNIGO_INFERENCE_TIMEOUT_S",
        "VULNIGO_MAX_CALLS",
        "VULNIGO_MAX_TOTAL_TOKENS",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_missing_base_url_is_reported_by_name(monkeypatch):
    set_env(monkeypatch, VULNIGO_INFERENCE_API_KEY="k")
    with pytest.raises(ConfigError, match="VULNIGO_INFERENCE_BASE_URL"):
        load()


def test_plain_http_is_refused_except_on_localhost(monkeypatch):
    set_env(
        monkeypatch,
        VULNIGO_INFERENCE_BASE_URL="http://infer.example.com/v1",
        VULNIGO_INFERENCE_API_KEY="k",
    )
    with pytest.raises(ConfigError, match="plain http"):
        load()

    set_env(
        monkeypatch,
        VULNIGO_INFERENCE_BASE_URL="http://127.0.0.1:8000/v1",
        VULNIGO_INFERENCE_API_KEY="k",
    )
    assert load().base_url == "http://127.0.0.1:8000/v1"


def test_trailing_slash_is_normalised(monkeypatch):
    set_env(
        monkeypatch,
        VULNIGO_INFERENCE_BASE_URL="https://infer.example.com/v1/",
        VULNIGO_INFERENCE_API_KEY="k",
        VULNIGO_MODEL_RED="a",
    )
    settings = load()
    assert settings.base_url == "https://infer.example.com/v1"
    assert settings.model_for("red") == "a"


def test_blank_model_values_are_dropped_not_kept_as_empty_names(monkeypatch):
    set_env(
        monkeypatch,
        VULNIGO_INFERENCE_BASE_URL="https://infer.example.com/v1",
        VULNIGO_INFERENCE_API_KEY="k",
        VULNIGO_MODEL_RED="  ",
    )
    assert load().models == {}


def test_budget_numbers_come_from_the_environment(monkeypatch):
    set_env(
        monkeypatch,
        VULNIGO_INFERENCE_BASE_URL="https://infer.example.com/v1",
        VULNIGO_INFERENCE_API_KEY="k",
        VULNIGO_MAX_CALLS="3",
        VULNIGO_MAX_TOTAL_TOKENS="900",
        VULNIGO_INFERENCE_TIMEOUT_S="7",
    )
    settings = load()
    assert (settings.max_calls, settings.max_total_tokens, settings.timeout_s) == (3, 900, 7)
