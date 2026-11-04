"""Smoke test the inference boundary before anything depends on it.

    python -m agents.smoke                # list models, then one validated call per role
    python -m agents.smoke --models-only

Reads only environment variables; prints the truth about the endpoint and exits
non-zero when the endpoint or the output is not usable. Run this the moment the VM
has credentials -- it is a five-minute check that removes the biggest unknown in the
four days.
"""

import sys
import time
from typing import Literal

from pydantic import BaseModel, Field

from .config import ConfigError, load
from .inference import Inference, MODEL_FAILURES


class Ping(BaseModel):
    ok: bool
    note: str = Field(min_length=1, max_length=120)
    mode: Literal["ping"] = "ping"


SYSTEM = (
    "You are a connectivity check for VULNIGO Lite. Reply with only a JSON object "
    'shaped like {"ok": true, "note": "<short>", "mode": "ping"}. No prose.'
)


def main(argv: list[str]) -> int:
    try:
        settings = load()
    except ConfigError as exc:
        print(f"config: {exc}", file=sys.stderr)
        return 2

    print(f"base url   {settings.base_url}")
    print(f"key        {'set, length ' + str(len(settings.api_key))}")
    print(f"models set {settings.models or 'NONE -- set VULNIGO_MODEL_RED/BLUE/MANAGER'}")
    print(f"timeouts   {settings.timeout_s}s | calls {settings.max_calls} | tokens {settings.max_total_tokens}")
    sys.stdout.flush()

    client = Inference(settings)

    print("\nGET /models")
    try:
        available = client.list_models()
    except MODEL_FAILURES as exc:
        print(f"  FAILED: {exc}", file=sys.stderr)
        print("  -> the base URL or the auth shape is wrong; fix that before writing prompts.")
        return 1
    print(f"  {len(available)} models available")
    for name in available[:40]:
        print(f"   - {name}")

    known = set(available)
    unknown = {role: name for role, name in settings.models.items() if name not in known}
    if unknown:
        print("\n  WARNING -- configured ids are not in the offered list:", file=sys.stderr)
        for role, name in sorted(unknown.items()):
            print(f"   - {role}: {name!r}", file=sys.stderr)
        print(
            "  This endpoint silently serves a flash variant for an unrecognised id, so\n"
            "  fix the names or the demo will run a model you did not choose.",
            file=sys.stderr,
        )

    if "--models-only" in argv:
        return 1 if unknown else 0

    if not settings.models:
        print("\nno role models configured; stopping after the model list.", file=sys.stderr)
        return 2

    failures = 0
    for role in ("red", "blue", "manager"):
        if role not in settings.models:
            continue
        print(f"\nask(role={role}, model={settings.models[role]})")
        started = time.monotonic()
        try:
            answer, usage = client.ask(role, SYSTEM, "Reply with the ping object.", Ping)
        except MODEL_FAILURES as exc:
            failures += 1
            print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            preview = getattr(exc, "raw_preview", "")
            if preview:
                print(f"  raw: {preview}", file=sys.stderr)
            continue
        print(f"  validated  {answer.model_dump()}")
        print(f"  tokens     {usage.total} in {usage.elapsed_s}s (wall {round(time.monotonic() - started, 2)}s)")

    print(f"\nbudget spent: {client.budget.calls} calls, {client.budget.tokens} tokens")
    if failures:
        print(f"{failures} role(s) failed -- see above", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
