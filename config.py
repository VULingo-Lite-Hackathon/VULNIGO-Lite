import os
from urllib.parse import urlparse

from pydantic import BaseModel, Field

DEFAULT_TIMEOUT_S = 45
DEFAULT_MAX_CALLS = 24
DEFAULT_MAX_COMPLETION_TOKENS = 1200
DEFAULT_MAX_TOTAL_TOKENS = 60000


class ConfigError(RuntimeError):
    pass


class Settings(BaseModel):
    base_url: str
    api_key: str
    models: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = DEFAULT_TIMEOUT_S
    max_calls: int = DEFAULT_MAX_CALLS
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS

    def model_for(self, role: str) -> str:
        try:
            return self.models[role]
        except KeyError:
            raise ConfigError(
                f"no model configured for {role!r}; set VULNIGO_MODEL_{role.upper()}"
            ) from None


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set -- see .env.example")
    return value


def load() -> Settings:
    base = _required("VULNIGO_INFERENCE_BASE_URL").rstrip("/")
    parsed = urlparse(base)

    # A plain-http base URL would ship the API key in the clear. Local development is
    # the only allowed exception, and it has no real key anyway.
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise ConfigError(f"VULNIGO_INFERENCE_BASE_URL is not a URL: {base!r}")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ConfigError(f"refusing to send a key over plain http: {base!r}")

    models = {
        role: value.strip()
        for role, value in (
            (role, os.getenv(f"VULNIGO_MODEL_{role.upper()}"))
            for role in ("red", "blue", "manager")
        )
        if value and value.strip()
    }

    return Settings(
        base_url=base,
        api_key=_required("VULNIGO_INFERENCE_API_KEY"),
        models=models,
        timeout_s=int(os.getenv("VULNIGO_INFERENCE_TIMEOUT_S", DEFAULT_TIMEOUT_S)),
        max_calls=int(os.getenv("VULNIGO_MAX_CALLS", DEFAULT_MAX_CALLS)),
        max_completion_tokens=int(
            os.getenv("VULNIGO_MAX_COMPLETION_TOKENS", DEFAULT_MAX_COMPLETION_TOKENS)
        ),
        max_total_tokens=int(os.getenv("VULNIGO_MAX_TOTAL_TOKENS", DEFAULT_MAX_TOTAL_TOKENS)),
    )
