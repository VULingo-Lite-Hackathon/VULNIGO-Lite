"""Bounded proof tests. Run INSIDE the sandbox only (no network, non-root, read-only /src).

Usage: python proof.py '<json spec>'
spec = {"file": "pkg/mod.py", "function": "f", "param": "x", "params": ["x"],
        "category": "command-injection" | "path-traversal",
        "token": "abc123", "mode": "attack" | "benign", "custom_payload": optional str}

command-injection (CWE-78): call the target with payloads whose only effect is writing a random token
    to <tmp>/vulnigo_proof. Confirmed = the token file appears.
path-traversal (CWE-22): plant a random token in <tmp>/vulnigo_secret.txt, OUTSIDE the directory the
    target is meant to read from, then call it with ../ and absolute-path payloads. Confirmed = the
    token comes back to the caller.
Nothing leaves the container either way.
"""
import contextlib
import importlib
import io
import json
import os
import sys

TMP = os.environ.get("VG_TMP", "/tmp")
SRC = os.environ.get("VG_SRC", "/src")
CANARY = os.path.join(TMP, "vulnigo_proof")
SECRET = os.path.join(TMP, "vulnigo_secret.txt")
RUN_DIR = os.path.join(TMP, "run")


def ci_payloads(token: str) -> list[str]:
    w = f"echo {token} > {CANARY}"
    return [f"x; {w} #", f"$({w})", f"`{w}`", f"x | {w} #", f"x\n{w}\n", f"x && {w} #"]


def pt_payloads() -> list[str]:
    name = os.path.basename(SECRET)
    return [f"../{name}", f"../../{name}", "../" * 8 + SECRET.lstrip("/\\"), SECRET, f"uploads/../../{name}"]


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
        if hasattr(ret, "read"):  # a returned file object: what the caller could read from it
            fobj = ret
            try:
                ret = fobj.read(65536)
            finally:
                with contextlib.suppress(Exception):
                    fobj.close()
    if isinstance(ret, bytes):
        ret = ret.decode(errors="replace")
    return ret, buf.getvalue()


def attack_ci(fn, spec, result) -> None:
    tries = [spec["custom_payload"]] if spec.get("custom_payload") else ci_payloads(spec["token"])
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


def attack_pt(fn, spec, result) -> None:
    token = spec["token"]
    with open(SECRET, "w") as f:
        f.write(f"vulnigo secret {token}\n")
    result["secret_file"] = SECRET
    tries = [spec["custom_payload"]] if spec.get("custom_payload") else pt_payloads()
    for p in tries:
        entry = {"payload": p}
        seen = ""
        try:
            ret, out = call(fn, spec["param"], spec["params"], p)
            entry["return"] = repr(ret)[:200]
            seen = f"{ret!s}\n{out}"
        except Exception as e:
            entry["exception"] = f"{type(e).__name__}: {e}"[:200]
        if token in seen:
            entry["leaked"] = f"vulnigo secret {token}"
            entry["reproduced"] = True
            result["confirmed"] = True
        result["attempts"].append(entry)
        if result["confirmed"]:
            break


def main() -> None:
    spec = json.loads(sys.argv[1])
    category = spec.get("category", "command-injection")
    os.makedirs(os.path.join(RUN_DIR, "uploads"), exist_ok=True)
    os.chdir(RUN_DIR)
    with open("uploads/sample.txt", "w") as f:
        f.write("vulnigo sample\n")
    result = {"mode": spec.get("mode", "attack"), "category": category, "attempts": [], "confirmed": False,
              "error": None}
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

    if category == "path-traversal":
        attack_pt(fn, spec, result)
    elif category == "command-injection":
        attack_ci(fn, spec, result)
    else:
        result["error"] = f"unknown category {category!r}"
    print("VG_RESULT " + json.dumps(result))


if __name__ == "__main__":
    main()
