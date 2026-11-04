"""Bounded proof test for CWE-78. Runs INSIDE the sandbox only (no network, non-root, read-only /src).

Usage: python proof.py '<json spec>'
spec = {"file": "pkg/mod.py", "function": "f", "param": "x", "params": ["x"],
        "token": "abc123", "mode": "attack" | "benign", "custom_payload": optional str}

The test calls the target function with a payload whose only effect is writing a random token to
/tmp/vulnigo_proof. Confirmed = the token file appears. Nothing leaves the container.
"""
import importlib
import io
import json
import os
import sys
import contextlib

CANARY = "/tmp/vulnigo_proof"
SRC = os.environ.get("VG_SRC", "/src")


def payloads(token: str) -> list[str]:
    w = f"echo {token} > {CANARY}"
    return [f"x; {w} #", f"$({w})", f"`{w}`", f"x | {w} #", f"x\n{w}\n", f"x && {w} #"]


def load(rel_file: str):
    sys.path.insert(0, SRC)
    mod = rel_file[:-3].replace("/", ".")
    if mod.endswith(".__init__"):
        mod = mod[: -len(".__init__")]
    return importlib.import_module(mod)


def call(fn, param: str, params: list[str], value: str):
    kwargs = {p: "" for p in params}
    kwargs[param] = value
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        ret = fn(**kwargs)
    return ret, buf.getvalue()


def main() -> None:
    spec = json.loads(sys.argv[1])
    os.makedirs("/tmp/run/uploads", exist_ok=True)
    os.chdir("/tmp/run")
    with open("uploads/sample.txt", "w") as f:
        f.write("vulnigo sample\n")
    result = {"mode": spec.get("mode", "attack"), "attempts": [], "confirmed": False, "error": None}
    try:
        fn = getattr(load(spec["file"]), spec["function"])
    except Exception as e:  # import failure -> inconclusive, never "safe"
        result["error"] = f"import failed: {type(e).__name__}: {e}"
        print("VG_RESULT " + json.dumps(result))
        return

    if spec.get("mode") == "benign":
        try:
            ret, out = call(fn, spec["param"], spec["params"], "sample.txt")
            result["benign"] = {"ok": True, "return": repr(ret)[:300], "output": out[:300]}
        except Exception as e:
            result["benign"] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}
        print("VG_RESULT " + json.dumps(result))
        return

    tries = [spec["custom_payload"]] if spec.get("custom_payload") else payloads(spec["token"])
    for p in tries:
        if os.path.exists(CANARY):
            os.remove(CANARY)
        entry = {"payload": p}
        try:
            ret, out = call(fn, spec["param"], spec["params"], p)
            entry["return"] = repr(ret)[:200]
        except Exception as e:
            entry["exception"] = f"{type(e).__name__}: {e}"[:200]
        if os.path.exists(CANARY):
            content = open(CANARY, errors="replace").read().strip()[:200]
            entry["canary"] = content
            if spec.get("custom_payload") or content == spec["token"]:
                entry["reproduced"] = True
                result["confirmed"] = True
        result["attempts"].append(entry)
        if result["confirmed"]:
            break
    print("VG_RESULT " + json.dumps(result))


if __name__ == "__main__":
    main()
