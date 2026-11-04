"""One boundary between our code and the model. Everything the model says passes through it.

Nothing here retries a network failure silently, and nothing here returns a default
object when the output will not validate. A caller that cannot get a valid answer is
expected to record `inconclusive`, which is the whole product rule.
"""

import json
import time
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from .config import Settings

T = TypeVar("T", bound=BaseModel)

REPAIR_ATTEMPTS = 2


class ModelUnavailable(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


class ModelSubstitution(RuntimeError):
    """The endpoint served a different model than the one we asked for.

    Vultr's own quickstart documents that an unrecognised model id silently falls back
    to a flash variant. Silently running a cheaper model while the report says the
    finding came from the model we named would be exactly the kind of claim this project
    refuses to make, so a mismatch is an error, not a footnote.
    """


class UnvalidatedOutput(RuntimeError):
    def __init__(self, message: str, attempts: int, raw: str):
        super().__init__(message)
        self.attempts = attempts
        self.raw_preview = raw[:400]


# Callers must handle all of these the same way: record what happened, degrade to an
# honest "inconclusive", and never present a partial run as a complete one.
MODEL_FAILURES = (
    ModelUnavailable,
    ModelSubstitution,
    UnvalidatedOutput,
    BudgetExhausted,
)


class Usage:
    def __init__(
        self,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        elapsed_s: float = 0.0,
        requested_model: str = "",
    ):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.elapsed_s = elapsed_s
        self.requested_model = requested_model

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class CallBudget:
    """Hard caps, checked before the call rather than discovered mid-demo."""

    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0

    def reserve(self) -> None:
        if self.calls >= self.max_calls:
            raise BudgetExhausted(f"call budget of {self.max_calls} exhausted")
        if self.tokens >= self.max_tokens:
            raise BudgetExhausted(f"token budget of {self.max_tokens} exhausted")

    def spend(self, usage: Usage) -> None:
        self.calls += 1
        self.tokens += usage.total


def extract_json(text: str) -> dict:
    """Take a JSON object out of whatever the model wrapped around it."""
    stripped = text.strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in the response")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object, got {type(payload).__name__}")
    return payload


class Inference:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.budget = CallBudget(settings.max_calls, settings.max_total_tokens)
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(settings.timeout_s, connect=min(10, settings.timeout_s))
        )

    def list_models(self) -> list[str]:
        response = self._get("/models")
        data = self._json(response)
        entries = data.get("data", data) if isinstance(data, dict) else data
        try:
            return [item["id"] for item in entries]
        except (TypeError, KeyError):
            raise ModelUnavailable(f"unexpected /models shape: {str(data)[:200]}") from None

    def ask(self, role: str, system: str, user: str, schema: type[T]) -> tuple[T, Usage]:
        model = self.settings.model_for(role)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        last_raw = ""
        for attempt in range(1, REPAIR_ATTEMPTS + 2):
            self.budget.reserve()
            usage, content = self._post(model, messages)
            self.budget.spend(usage)
            last_raw = content

            try:
                return schema.model_validate(extract_json(content)), usage
            except (ValueError, json.JSONDecodeError, ValidationError) as exc:
                messages.append({"role": "assistant", "content": content})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"That reply could not be used: {type(exc).__name__}: {exc}. "
                            "Reply again with only a valid JSON object matching the schema. "
                            "No prose, no code fences."
                        ),
                    }
                )

        raise UnvalidatedOutput(
            f"{role} output failed validation after {REPAIR_ATTEMPTS + 1} attempts",
            REPAIR_ATTEMPTS + 1,
            last_raw,
        )

    def _post(self, model: str, messages: list[dict]) -> tuple[Usage, str]:
        started = time.monotonic()
        response = self._post_json(
            "/chat/completions",
            {
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": self.settings.max_completion_tokens,
            },
        )
        elapsed = round(time.monotonic() - started, 2)
        body = self._json(response)

        try:
            choice = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ModelUnavailable(f"unexpected response shape: {str(body)[:200]}") from None

        usage_body = body.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_body.get("prompt_tokens", 0)),
            completion_tokens=int(usage_body.get("completion_tokens", 0)),
            elapsed_s=elapsed,
            requested_model=model,
        )

        served = body.get("model")
        if isinstance(served, str) and served and served != model:
            raise ModelSubstitution(f"asked for {model!r}, the endpoint served {served!r}")

        return usage, choice or ""

    def _json(self, response: httpx.Response) -> dict:
        try:
            return response.json()
        except ValueError as exc:
            # A proxy or gateway can answer 200 with an HTML error page. That must be a
            # recorded model failure, not a traceback escaping the pointer path.
            raise ModelUnavailable(
                f"endpoint returned non-JSON ({exc.__class__.__name__})"
            ) from exc

    def _get(self, path: str) -> httpx.Response:
        return self._send("GET", path)

    def _post_json(self, path: str, payload: dict) -> httpx.Response:
        return self._send("POST", path, json=payload)

    def _send(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.settings.base_url}{path}"
        try:
            response = self._client.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self.settings.api_key}"},
                **kwargs,
            )
        except httpx.TimeoutException as exc:
            raise ModelUnavailable(
                f"{method} {path} timed out after {self.settings.timeout_s}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelUnavailable(f"{method} {path} failed: {exc.__class__.__name__}") from exc

        if response.status_code >= 400:
            # Redact first, THEN truncate. Cutting to 300 characters first can leave the
            # head of a key standing, and this text goes into logs and the UI.
            detail = response.text.replace(self.settings.api_key, "[redacted]")
            detail = detail.replace("Bearer ", "Bearer [redacted] ")[:300]
            raise ModelUnavailable(f"{method} {path} -> {response.status_code}: {detail}")

        return response
