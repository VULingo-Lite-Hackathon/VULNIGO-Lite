"""Sandbox service: every execution of repository code happens here, inside a disposable container.

Container policy: no network, non-root (nobody), read-only root fs, read-only code mount,
small tmpfs, all capabilities dropped, no-new-privileges, CPU/memory/PID/time limits, no env
vars from the host, no host sockets. Optional gVisor via SANDBOX_RUNTIME=runsc.

Only allowlisted actions exist (probe / proof / benign / regression). Agents can request an
action by name; they can never supply a shell command.
"""
import asyncio
import datetime
import json
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
import weakref
from pathlib import Path

from . import config, store

HARNESS = Path(__file__).resolve().parent / "harness"
_docker_ok: bool | None = None
MAX_OUTPUT_BYTES = 64 * 1024  # per run; more than any real test report needs
CAP_NOTICE = "\n[output cut at 64 KB]"
KILL_TIMEOUT_S = 20  # how long `docker kill` may take before the backend stops waiting for it
MAX_CONTAINERS = int(os.getenv("SANDBOX_MAX_CONTAINERS", "4"))  # sandbox containers alive at once per event loop (the backend runs one)
_SBX_NAME = re.compile(r"sbx_[0-9a-f]{8}")
STALE_MARGIN_S = 30  # a container older than SANDBOX_TIMEOUT + this cannot belong to a live run
_swept = False
_sweeping: asyncio.Future | None = None
_slots: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()  # event loop -> Semaphore (one loop each)


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


GVISOR_MIN_PIDS = 256  # gVisor counts its own host threads (~2.5 per process); below this a modest test crashes the sandbox


def pids_limit() -> str:
    """The --pids-limit to enforce. Under gVisor (runsc) the cgroup limit also counts the sentry's host threads, and
    crossing it kills the whole sandbox silently, so the limit is raised to a floor that still bounds a fork bomb."""
    if config.SANDBOX_RUNTIME == "runsc":
        return str(max(int(config.SANDBOX_PIDS), GVISOR_MIN_PIDS))
    return str(config.SANDBOX_PIDS)


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
        "pids": pids_limit(),
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
           "--pids-limit", pids_limit(),
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


async def _drain(stream, limit: int) -> tuple[bytes, bool]:
    """Read at most `limit` bytes. Returns (data, cut). Stops reading as soon as the limit is passed."""
    buf = bytearray()
    while chunk := await stream.read(65536):
        room = limit - len(buf)
        buf += chunk[:max(room, 0)]
        if len(chunk) > room:
            return bytes(buf), True
    return bytes(buf), False


async def _docker(*args: str, timeout: float = KILL_TIMEOUT_S) -> tuple[int | None, str]:
    """Run a docker CLI command. Returns (exit code, stdout); (None, "") if it did not answer in time or failed to start."""
    try:
        p = await asyncio.create_subprocess_exec("docker", *args, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        return None, ""
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        await p.wait()
        return None, ""
    return p.returncode, out.decode(errors="replace")


async def sweep_leftovers() -> int:
    """Remove sandbox containers a crashed or restarted backend left behind. Returns how many were removed.

    Only containers older than any live run can be (SANDBOX_TIMEOUT plus a margin) are removed, so a second
    backend or a test run sharing this Docker daemon keeps its running containers.
    """
    rc, out = await _docker("ps", "-a", "--filter", "name=sbx_", "--format", "{{.Names}}")
    if rc != 0:
        return 0
    names = [n for n in out.split() if _SBX_NAME.fullmatch(n)]
    if not names:
        return 0
    _, info = await _docker("inspect", "--format", "{{.Name}} {{.Created}}", *names)
    now = datetime.datetime.now(datetime.timezone.utc)
    removed = 0
    for line in info.splitlines():
        try:
            name, created = line.split()
            born = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        name = name.lstrip("/")
        if name in names and (now - born).total_seconds() > config.SANDBOX_TIMEOUT + STALE_MARGIN_S:
            await _docker("rm", "-f", name)
            removed += 1
    return removed


async def _safe_sweep() -> int:
    try:
        return await sweep_leftovers()
    except Exception:  # a broken sweep must never stop the sandbox from running tests
        return 0


async def _sweep_once() -> None:
    """Sweep once per process. Every first-wave run waits for the same task, so the sweep never meets our own
    containers, and shield() keeps one cancelled run from cancelling the sweep for the runs after it."""
    global _swept, _sweeping
    if _swept:
        return
    loop = asyncio.get_running_loop()
    if _sweeping is None or _sweeping.get_loop() is not loop or (_sweeping.done() and _sweeping.cancelled()):
        _sweeping = asyncio.ensure_future(_safe_sweep())  # a task left by a finished loop is dead weight
    await asyncio.shield(_sweeping)
    _swept = True


async def _kill(proc, kill_name: str | None) -> None:
    # The docker client goes first. After a cut nobody reads its output, and the daemon can block writing to it;
    # a `docker kill` sent while that client is alive waits behind the block (seen with a flooding test on Docker Desktop).
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    await proc.wait()
    if kill_name:
        rc, _ = await _docker("kill", kill_name)
        if rc != 0:  # no answer or no such container: force-remove so nothing keeps running after the test
            await _docker("rm", "-f", kill_name)


async def _exec(argv: list[str], env: dict | None, cwd: str | None, timeout: int,
                kill_name: str | None) -> tuple[int | None, str, bool, bool]:
    """Run argv. Returns (exit code, output, timed_out, truncated).

    Output is read as a stream and cut at MAX_OUTPUT_BYTES, so a program that prints forever
    cannot fill the backend's memory. On a cut or a timeout the container is killed and the exit code is None.
    """
    proc = await asyncio.create_subprocess_exec(*argv, env=env, cwd=cwd,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)

    async def collect() -> tuple[bytes, bool]:
        out, cut = await _drain(proc.stdout, MAX_OUTPUT_BYTES)
        if not cut:
            await proc.wait()
        return out, cut

    try:
        out, cut = await asyncio.wait_for(collect(), timeout)
    except asyncio.TimeoutError:
        await _kill(proc, kill_name)
        return None, f"timed out after {timeout}s (killed)", True, False
    except asyncio.CancelledError:  # a battle abort or shutdown must not leave the container running
        await asyncio.shield(_kill(proc, kill_name))
        raise
    if cut:
        await _kill(proc, kill_name)
        return None, out.decode(errors="replace") + CAP_NOTICE, False, True
    return proc.returncode, out.decode(errors="replace"), False, False


_TOKEN = re.compile(r"[A-Za-z0-9]{1,64}")
_SPEC_KEYS = {"file", "function", "param", "params", "category", "token", "custom_payload", "mode"}


def _ident(x) -> bool:
    # str.isidentifier, not a regex: the scanner takes names from ast, which allows unicode, and `$` would let "f\n" through.
    return isinstance(x, str) and x.isidentifier()


def _validate_spec(spec, code_dir) -> None:
    """Reject any proof/benign spec the scanner could not have produced. Raises ValueError; nothing has run yet."""
    if not isinstance(spec, dict):
        raise ValueError("spec must be an object")
    extra = set(spec) - _SPEC_KEYS
    if extra:
        raise ValueError(f"unknown spec keys: {sorted(extra)}")
    f = spec.get("file")
    if (not isinstance(f, str) or not f.endswith(".py") or ".." in f.split("/") or f.startswith("/")
            or "\\" in f or ":" in f):
        raise ValueError("spec.file must be a relative .py path inside the repository")
    # proof.py imports file[:-3] with "/" turned into "."; a dotted stem or a stdlib-named first segment would
    # load some other module (stdlib wins), so a proof on it would say nothing about the repo file checked here.
    if "." in f[:-3] or f.split("/")[0].removesuffix(".py") in sys.stdlib_module_names:
        raise ValueError("spec.file would be imported as a different module than the repository file")
    root = Path(code_dir).resolve()
    target = (root / f).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError("spec.file is not a regular file inside the repository")
    fn = spec.get("function")
    if not _ident(fn) or (fn.startswith("__") and fn.endswith("__")):
        raise ValueError("spec.function must be an identifier and not a dunder name")
    param, params = spec.get("param"), spec.get("params")
    if not _ident(param):
        raise ValueError("spec.param must be an identifier")
    # param may be keyword-only, which the scanner leaves out of params, so it is not required to be in params.
    if not isinstance(params, list) or not all(_ident(x) for x in params):
        raise ValueError("spec.params must be a list of identifiers")
    if spec.get("category", "command-injection") not in ("command-injection", "path-traversal"):
        raise ValueError("spec.category is not a known category")
    if "token" in spec and not (isinstance(spec["token"], str) and _TOKEN.fullmatch(spec["token"])):
        raise ValueError("spec.token must be 1-64 alphanumerics")
    cp = spec.get("custom_payload")
    if "custom_payload" in spec and (not isinstance(cp, str) or len(cp) > 300):
        raise ValueError("spec.custom_payload must be a string of at most 300 characters")
    if spec.get("mode") not in (None, "benign", "attack"):
        raise ValueError("spec.mode must be benign or attack")


def _slot() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    if loop not in _slots:
        _slots[loop] = asyncio.Semaphore(MAX_CONTAINERS)
    return _slots[loop]


async def run(run_id: str, action: str, code_dir: str, spec: dict | None = None,
              is_demo: bool = False, label: str = "") -> dict:
    """Run one allowlisted action and record it as a test_run row. Returns that row."""
    if action not in ACTIONS:
        raise ValueError(f"action {action!r} is not allowlisted")
    if action in ("proof", "benign"):
        _validate_spec(spec, code_dir)
    spec = spec or {}
    argv = ACTIONS[action](spec)
    env_id = "sbx_" + uuid.uuid4().hex[:8]
    started = time.time()
    sandboxed = await docker_available()
    if sandboxed:
        await _sweep_once()
        cmd = _docker_cmd(env_id, code_dir, argv)
        async with _slot():
            code, out, timed_out, truncated = await _exec(cmd, None, None, config.SANDBOX_TIMEOUT + 10, env_id)
        shown = " ".join(argv[:3]) + (" <spec>" if len(argv) > 3 and action != "regression" else " " + " ".join(argv[3:]))
    elif is_demo and config.ALLOW_UNSANDBOXED_DEMO:
        # Dev-only path for the bundled demo repo on a machine without Docker. Clearly labelled.
        tmp = tempfile.mkdtemp(prefix="vg_dev_")
        local = [sys.executable] + [a.replace("/harness", str(HARNESS)).replace("/src", code_dir) for a in argv[1:]]
        env = {"PATH": os.environ.get("PATH", ""), "VG_SRC": code_dir, "VG_TMP": tmp, "PYTHONDONTWRITEBYTECODE": "1",
               "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
        code, out, timed_out, truncated = await _exec(local, env, tmp, config.SANDBOX_TIMEOUT, None)
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
    outcome = _outcome(action, code, out, parsed, timed_out, truncated)
    row = {"id": store.new_id("tr"), "run_id": run_id, "kind": action, "command": shown, "env_id": env_id,
           "exit_code": code, "output": out[-4000:], "started": started, "ended": time.time(),
           "outcome": outcome, "sandboxed": 1 if sandboxed else 0,
           "data": {"label": label, "result": parsed, "spec": {k: v for k, v in spec.items() if k != "token"},
                    "timed_out": timed_out, "truncated": truncated, "policy": describe_policy() if sandboxed else None}}
    return store.insert("test_runs", row)


def _outcome(action: str, code, out: str, parsed: dict | None, timed_out: bool, truncated: bool = False) -> str:
    """Map raw results to pass / fail / inconclusive. 'pass' always means 'the check succeeded'.

    proof:      pass = vulnerability reproduced, fail = not reproduced, inconclusive = could not run
    benign:     pass = function still works on normal input
    regression: pass = pytest exit 0, fail = tests failed, inconclusive = no tests / error
    probe:      pass = every escape attempt was blocked
    """
    if timed_out or truncated:  # cut output can hold a forged or half-written result line
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
