"""OpenAI-compatible client for Vultr Serverless Inference. Model output is untrusted input."""
import json
import re

import httpx

from . import config


class LLMError(Exception):
    pass


_models_cache: list[str] | None = None


def enabled() -> bool:
    return bool(config.INFERENCE_KEY)


async def list_models() -> list[str]:
    global _models_cache
    if _models_cache is None:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(f"{config.INFERENCE_BASE_URL}/models",
                            headers={"Authorization": f"Bearer {config.INFERENCE_KEY}"})
            r.raise_for_status()
            _models_cache = [m["id"] for m in r.json().get("data", []) if "id" in m]
    return _models_cache


_PREFERRED = ("deepseek", "llama", "qwen", "mistral", "kimi", "gpt-oss")


async def pick_model(role: str) -> str:
    """Red and Blue use different model families when possible (diversity is a mitigation only)."""
    explicit = {"red": config.RED_MODEL, "blue": config.BLUE_MODEL, "manager": config.MANAGER_MODEL}.get(role)
    if explicit:
        return explicit
    models = [m for m in await list_models() if not re.search(r"embed|whisper|tts|image|vision-only|rerank", m, re.I)]
    if not models:
        raise LLMError("no chat models available on the inference endpoint")
    ranked = sorted(models, key=lambda m: next((i for i, p in enumerate(_PREFERRED) if p in m.lower()), 99))
    families: list[str] = []
    for m in ranked:
        fam = next((p for p in _PREFERRED if p in m.lower()), m)
        if fam not in families:
            families.append(fam)
    pick_family = {"red": 0, "blue": 1 if len(families) > 1 else 0, "manager": 0}[role] if role in ("red", "blue", "manager") else 0
    fam = families[pick_family]
    return next(m for m in ranked if fam in m.lower() or m == fam)


def _extract_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = m.group(1) if m else None
    if candidate is None:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            raise LLMError("model did not return JSON")
        candidate = text[start:end + 1]
    try:
        return json.loads(candidate)
    except ValueError as e:
        raise LLMError(f"model returned invalid JSON: {e}") from e


async def chat_json(role: str, system: str, user: str, max_tokens: int = 1200) -> tuple[dict, str]:
    """Return (parsed_json, model_id). Raises LLMError on any failure - callers fall back honestly."""
    if not enabled():
        raise LLMError("no inference key configured")
    try:
        model = await pick_model(role)
        async with httpx.AsyncClient(timeout=config.LLM_TIMEOUT) as c:
            r = await c.post(f"{config.INFERENCE_BASE_URL}/chat/completions",
                             headers={"Authorization": f"Bearer {config.INFERENCE_KEY}"},
                             json={"model": model, "temperature": 0.2, "max_tokens": max_tokens,
                                   "messages": [{"role": "system", "content": system},
                                                {"role": "user", "content": user}]})
        if r.status_code >= 400:
            raise LLMError(f"inference HTTP {r.status_code}: {r.text[:200]}")
        content = r.json()["choices"][0]["message"]["content"] or ""
    except httpx.HTTPError as e:
        raise LLMError(f"inference request failed: {type(e).__name__}") from e
    except (KeyError, IndexError, ValueError) as e:
        raise LLMError("unexpected inference response shape") from e
    return _extract_json(content), model
