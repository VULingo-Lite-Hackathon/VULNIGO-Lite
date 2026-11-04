"""Sandbox service: every execution of repository code happens here, inside a disposable container.

Container policy: no network, non-root (nobody), read-only root fs, read-only code mount,
small tmpfs, all capabilities dropped, no-new-privileges, CPU/memory/PID/time limits, no env
vars from the host, no host sockets. Optional gVisor via SANDBOX_RUNTIME=runsc.

Only allowlisted actions exist (probe / proof / benign / regression). Agents can request an
action by name; they can never supply a shell command.
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

from . import config, store

HARNESS = Path(__file__).resolve().parent / "harness"
_docker_ok: bool | None = None


async def docker_available() -> bool:
    global _docker_ok
    if _docker_ok is None:
        if not shutil.which("docker"):
            _docker_ok = False
        else:
            try:
                p = await asyncio.create_subprocess_exec("docker", "image", "inspect", config.SANDBOX_IMAGE,
                                                         stdout=asyncio.subprocess.DEVNULL,
                                                         stderr=asyncio.subprocess.DEVNULL)
                _docker_ok = (await asyncio.wait_for(p.wait(), 15)) == 0
            except (OSError, asyncio.TimeoutError):
                _docker_ok = False
    return _docker_ok


def describe_policy() -> dict:
    return {
        "network": "none",
        "user": "65534:65534 (nobody)",
        "root_fs": "read-only",
        "code_mount": "read-only",
        "tmpfs": "/tmp 32MB, noexec, nosuid",
        "open_files": 256,
        "stop_signal": "SIGKILL",
        "memory": config.SANDBOX_MEMORY,
        "cpus": config.SANDBOX_CPUS,
        "pids": config.SANDBOX_PIDS,
        "timeout_s": config.SANDBOX_TIMEOUT,
        "capabilities": "all dropped, no-new-privileges",
        "runtime": config.SANDBOX_RUNTIME or "runc",
        "host_env": "none passed",
    }


ACTIONS = {
    "probe": lambda spec: ["python", "/harness/probe.py"],
    "proof": lambda spec: ["python", "/harness/proof.py", json.dumps(spec)],
    "benign": lambda spec: ["python", "/harness/proof.py", json.dumps({**spec, "mode": "benign"})],
    "regression": lambda spec: ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir=/src", "/src"],
}


def _docker_cmd(name: str, code_dir: str, argv: list[str]) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", name,
           "--network", "none",
           "--user", "65534:65534",
           "--read-only",
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
           "--memory", config.SANDBOX_MEMORY, "--memory-swap", config.SANDBOX_MEMORY,
           "--cpus", config.SANDBOX_CPUS,
           "--pids-limit", config.SANDBOX_PIDS,
           "--ulimit", "nofile=256:256",
           "--stop-signal", "SIGKILL",
           "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true",
           "--label", "vulnigo.job=" + name,
           "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "HOME=/tmp", "--env", "VG_SRC=/src",
           "-v", f"{code_dir}:/src:ro",
           "-v", f"{HARNESS}:/harness:ro",
           "-w", "/tmp"]
    if config.SANDBOX_RUNTIME:
        cmd += ["--runtime", config.SANDBOX_RUNTIME]
    return cmd + [config.SANDBOX_IMAGE] + argv


def _parse(output: str) -> dict | None:
    for line in reversed(output.splitlines()):
        if line.startswith("VG_RESULT "):
            try:
                return json.loads(line[len("VG_RESULT "):])
            except ValueError:
                return None
    return None


async def _exec(argv: list[str], env: dict | None, cwd: str | None, timeout: int,
                kill_name: str | None) -> tuple[int | None, str, bool]:
    proc = await asyncio.create_subprocess_exec(*argv, env=env, cwd=cwd,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        return proc.returncode, out.decode(errors="replace"), False
    except asyncio.TimeoutError:
        if kill_name:
            k = await asyncio.create_subprocess_exec("docker", "kill", kill_name,
                                                     stdout=asyncio.subprocess.DEVNULL,
                                                     stderr=asyncio.subprocess.DEVNULL)
            await k.wait()
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return None, f"timed out after {timeout}s (killed)", True


async def run(run_id: str, action: str, code_dir: str, spec: dict | None = None,
              is_demo: bool = False, label: str = "") -> dict:
    """Run one allowlisted action and record it as a test_run row. Returns that row."""
    if action not in ACTIONS:
        raise ValueError(f"action {action!r} is not allowlisted")
    spec = spec or {}
    argv = ACTIONS[action](spec)
    env_id = "sbx_" + uuid.uuid4().hex[:8]
    started = time.time()
    sandboxed = await docker_available()
    if sandboxed:
        cmd = _docker_cmd(env_id, code_dir, argv)
        code, out, timed_out = await _exec(cmd, None, None, config.SANDBOX_TIMEOUT + 10, env_id)
        shown = " ".join(argv[:3]) + (" <spec>" if len(argv) > 3 and action != "regression" else " " + " ".join(argv[3:]))
    elif is_demo and config.ALLOW_UNSANDBOXED_DEMO:
        # Dev-only path for the bundled demo repo on a machine without Docker. Clearly labelled.
        tmp = tempfile.mkdtemp(prefix="vg_dev_")
        local = [sys.executable] + [a.replace("/harness", str(HARNESS)).replace("/src", code_dir) for a in argv[1:]]
        env = {"PATH": os.environ.get("PATH", ""), "VG_SRC": code_dir, "PYTHONDONTWRITEBYTECODE": "1",
               "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
        code, out, timed_out = await _exec(local, env, tmp, config.SANDBOX_TIMEOUT, None)
        shutil.rmtree(tmp, ignore_errors=True)
        env_id = "UNSANDBOXED-DEV"
        shown = "[UNSANDBOXED DEV] " + " ".join(argv[:3])
    else:
        row = {"id": store.new_id("tr"), "run_id": run_id, "kind": action, "command": " ".join(argv[:3]),
               "env_id": None, "exit_code": None,
               "output": "Sandbox unavailable: Docker sandbox image not found on this host. Test not run.",
               "started": started, "ended": time.time(), "outcome": "inconclusive", "sandboxed": 0,
               "data": {"label": label, "policy": describe_policy()}}
        return store.insert("test_runs", row)

    parsed = _parse(out) if action != "regression" else None
    outcome = _outcome(action, code, out, parsed, timed_out)
    row = {"id": store.new_id("tr"), "run_id": run_id, "kind": action, "command": shown, "env_id": env_id,
           "exit_code": code, "output": out[-4000:], "started": started, "ended": time.time(),
           "outcome": outcome, "sandboxed": 1 if sandboxed else 0,
           "data": {"label": label, "result": parsed, "spec": {k: v for k, v in spec.items() if k != "token"},
                    "timed_out": timed_out, "policy": describe_policy() if sandboxed else None}}
    return store.insert("test_runs", row)


def _outcome(action: str, code, out: str, parsed: dict | None, timed_out: bool) -> str:
    """Map raw results to pass / fail / inconclusive. 'pass' always means 'the check succeeded'.

    proof:      pass = vulnerability reproduced, fail = not reproduced, inconclusive = could not run
    benign:     pass = function still works on normal input
    regression: pass = pytest exit 0, fail = tests failed, inconclusive = no tests / error
    probe:      pass = every escape attempt was blocked
    """
    if timed_out:
        return "inconclusive"
    if action == "regression":
        if code == 0:
            return "pass"
        if code == 5 or "no tests ran" in out:
            return "inconclusive"
        return "fail" if code == 1 else "inconclusive"
    if parsed is None or parsed.get("error"):
        return "inconclusive"
    if action == "proof":
        return "pass" if parsed.get("confirmed") else "fail"
    if action == "benign":
        return "pass" if parsed.get("benign", {}).get("ok") else "fail"
    if action == "probe":
        return "pass" if parsed.get("all_blocked") else "fail"
    return "inconclusive"
