"""Real-Docker checks of sandbox.run: the Day 2 path "run tests safely in the sandbox, apply a patch, re-run".

These need a Docker daemon and the image `vulnigo-sandbox:latest` (`docker build -t vulnigo-sandbox:latest sandbox/`).
Without them every test here is skipped, so the normal `pytest tests` stays Docker-free.
Run only these:  pytest tests/test_sandbox_docker.py -m docker
"""
import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from vulnigo import config, sandbox

pytestmark = pytest.mark.docker

ROOT = Path(__file__).resolve().parent.parent
SPEC = {"file": "filedesk/tools.py", "function": "file_size", "param": "filename",
        "params": ["filename"], "token": "VGdocker123456", "category": "command-injection"}


def _docker_ready() -> bool:
    try:
        return asyncio.run(sandbox.docker_available())
    except Exception:
        return False


if not _docker_ready():
    pytest.skip("needs a Docker daemon and the vulnigo-sandbox:latest image", allow_module_level=True)


def run(kind, code_dir, spec=None, label=""):
    return asyncio.run(sandbox.run("dockertest", kind, str(code_dir), spec, label=label))


def readable_by_sandbox(root: Path) -> Path:
    # pytest's tmp dirs are 0700; the container runs as uid 65534 and sees the bind mount's host modes on Linux.
    for dirpath, _dirs, files in os.walk(root):
        os.chmod(dirpath, 0o755)
        for f in files:
            os.chmod(os.path.join(dirpath, f), 0o644)
    return root


def copy_demo(tmp_path: Path) -> Path:
    dst = tmp_path / "src"
    shutil.copytree(ROOT / "demo_repo", dst, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return readable_by_sandbox(dst)


def sandbox_containers() -> list[str]:
    # `docker kill` returns before the --rm removal finishes, so give removal a few seconds.
    left = []
    for _ in range(10):
        left = subprocess.run(["docker", "ps", "-a", "--filter", "name=sbx_", "--format", "{{.Names}}"],
                              capture_output=True, text=True).stdout.split()
        if not left:
            break
        time.sleep(0.5)
    return left


@pytest.fixture
def short_timeout(monkeypatch):
    monkeypatch.setattr(config, "SANDBOX_TIMEOUT", 5)


def test_proof_reproduces_the_planted_bug_inside_the_sandbox(tmp_path):
    r = run("proof", copy_demo(tmp_path), dict(SPEC))
    assert r["sandboxed"]
    assert r["outcome"] == "pass", r["output"][-300:]


def test_patch_applied_to_the_working_copy_changes_the_retest_result(tmp_path):
    # Day 2 acceptance: the same test, re-run after the patch, reports the real result.
    work = copy_demo(tmp_path)
    tools = work / "filedesk" / "tools.py"
    before = run("proof", work, dict(SPEC))
    assert before["outcome"] == "pass"  # exploit works on the unpatched copy

    from vulnigo import patcher, scanner
    finding = next(f for f in scanner.scan_command_injection(work) if f["function"] == "file_size")
    fixed = patcher.deterministic_fix(str(work), finding)
    assert fixed is not None
    tools.write_text(fixed["new_text"], encoding="utf-8")

    after = run("proof", work, dict(SPEC))
    assert after["outcome"] == "fail", f"expected the exploit to be refused, got {after['outcome']}: {after['output'][-300:]}"
    benign = run("benign", work, dict(SPEC))
    assert benign["outcome"] == "pass", benign["output"][-300:]
    regression = run("regression", work)
    assert regression["outcome"] == "pass", regression["output"][-300:]


def test_a_test_that_prints_forever_is_cut_and_inconclusive(tmp_path, short_timeout):
    flood = tmp_path / "src"
    flood.mkdir()
    (flood / "test_flood.py").write_text(
        "import sys\n\ndef test_flood():\n    while True:\n        sys.stdout.write('x' * 65536)\n        sys.stdout.flush()\n")
    started = time.monotonic()
    readable_by_sandbox(flood)
    r = run("regression", flood)
    assert r["outcome"] == "inconclusive"
    assert r["data"]["truncated"] is True
    assert len(r["output"]) <= 4100
    assert time.monotonic() - started < 20
    assert sandbox_containers() == []


def test_a_test_that_hangs_is_killed_at_the_timeout(tmp_path, short_timeout):
    hang = tmp_path / "src"
    hang.mkdir()
    (hang / "test_hang.py").write_text("import time\n\ndef test_hang():\n    time.sleep(600)\n")
    started = time.monotonic()
    readable_by_sandbox(hang)
    r = run("regression", hang)
    assert r["outcome"] == "inconclusive"
    assert r["data"]["timed_out"] is True
    assert time.monotonic() - started < 30
    assert sandbox_containers() == []
