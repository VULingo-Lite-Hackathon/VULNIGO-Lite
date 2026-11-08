"""sandbox/containment.sh must attack the image with the same limits the backend enforces,
or a green containment run says nothing about production."""
import re
import shlex
from pathlib import Path

from vulnigo import sandbox

SCRIPT = Path(__file__).resolve().parent.parent / "sandbox" / "containment.sh"
SHARED = ["--network", "--user", "--memory", "--memory-swap", "--cpus", "--pids-limit", "--ulimit",
          "--stop-signal", "--cap-drop", "--security-opt", "--tmpfs"]


def _flags(tokens: list[str]) -> dict:
    out, i = {}, 0
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("--") and i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
            out[t] = tokens[i + 1]
            i += 2
        else:
            out[t] = True
            i += 1
    return out


def _script_base() -> dict:
    m = re.search(r"^BASE=\((.*?)\)\s*$", SCRIPT.read_text(), re.S | re.M)
    assert m, "BASE=(...) not found in containment.sh"
    return _flags(shlex.split(m.group(1).replace("\\n", " ")))


def _backend() -> dict:
    cmd = sandbox._docker_cmd("sbx_test", "/code", ["python", "x"])
    return _flags(cmd[2:cmd.index(sandbox.config.SANDBOX_IMAGE)])


def _defaults(monkeypatch):
    # The script hard-codes the defaults; an SANDBOX_* override on this machine is not drift.
    for name, value in (("SANDBOX_MEMORY", "256m"), ("SANDBOX_CPUS", "0.5"), ("SANDBOX_PIDS", "64"), ("SANDBOX_RUNTIME", "")):
        monkeypatch.setattr(sandbox.config, name, value)


def test_script_uses_the_backend_limits(monkeypatch):
    _defaults(monkeypatch)
    script, backend = _script_base(), _backend()
    for flag in SHARED:
        assert script.get(flag) == backend.get(flag), f"{flag}: script={script.get(flag)!r} backend={backend.get(flag)!r}"


def test_script_has_the_backend_boolean_flags(monkeypatch):
    _defaults(monkeypatch)
    script, backend = _script_base(), _backend()
    assert script.get("--read-only") is True and backend.get("--read-only") is True
    assert script.get("--rm") is True and backend.get("--rm") is True


def test_script_mounts_the_probes_read_only():
    assert _script_base()["--volume"].endswith(":/probe:ro")


def test_script_banner_names_the_enforced_pid_limit(monkeypatch):
    _defaults(monkeypatch)
    assert f"pids-limit {sandbox.config.SANDBOX_PIDS}" in SCRIPT.read_text()


def _pids_flag(monkeypatch, runtime, pids="64"):
    monkeypatch.setattr(sandbox.config, "SANDBOX_RUNTIME", runtime)
    monkeypatch.setattr(sandbox.config, "SANDBOX_PIDS", pids)
    return _backend()["--pids-limit"]


def test_pid_limit_is_the_configured_one_under_the_default_runtime(monkeypatch):
    assert _pids_flag(monkeypatch, "") == "64"


def test_gvisor_gets_a_pid_limit_it_can_survive(monkeypatch):
    # Measured on Ubuntu 24.04 + runsc 20261102: gVisor counts its own host threads (about 2.5 per process) against the
    # cgroup limit, and crossing it kills the whole sandbox silently (exit 2). 64 crashed at ~25 processes; 256 holds 100.
    assert int(_pids_flag(monkeypatch, "runsc")) >= 256


def test_an_explicit_higher_pid_limit_is_kept_under_gvisor(monkeypatch):
    assert _pids_flag(monkeypatch, "runsc", "512") == "512"


def test_describe_policy_reports_the_enforced_pid_limit(monkeypatch):
    monkeypatch.setattr(sandbox.config, "SANDBOX_RUNTIME", "runsc")
    monkeypatch.setattr(sandbox.config, "SANDBOX_PIDS", "64")
    assert str(sandbox.describe_policy()["pids"]) == _backend()["--pids-limit"]
