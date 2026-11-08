"""Clone limits: the watchdog kills a clone that grows past its byte limit or outlives its timeout,
and removes the partial destination on every failure. Offline: Python children stand in for git."""
import asyncio
import os
import sys
import time

import pytest

from vulnigo import config, intake
from vulnigo.intake import IntakeError

MB = 1024 * 1024

# Paced so one poll interval cannot write gigabytes on a fast disk. Bounded so a mutated run
# (watchdog kill removed) cannot leave an endless writer behind. It recreates its directory on
# every loop, so a survivor that outlives the watchdog is visible as a directory coming back.
FLOOD = """
import os, sys, time
d = sys.argv[1]
blob = b"x" * 65536
for i in range(200):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"f{i}.bin"), "wb") as f:
        f.write(blob)
    time.sleep(0.005)
"""

# Sleeps past the timeout, then writes into its directory. Only a killed child stays silent.
LATE_WRITER = """
import os, sys, time
time.sleep(float(sys.argv[2]))
os.makedirs(sys.argv[1], exist_ok=True)
open(os.path.join(sys.argv[1], "late.txt"), "w").close()
"""


def _run(argv, watch, max_bytes, timeout):
    return asyncio.run(intake._run_watched(argv, watch, max_bytes, timeout, dict(os.environ)))


def test_growth_past_limit_kills_the_process_and_removes_the_directory(tmp_path):
    watch = tmp_path / "snap"
    start = time.monotonic()
    with pytest.raises(IntakeError, match="larger than"):
        _run([sys.executable, "-c", FLOOD, str(watch)], watch, MB, 30)
    assert time.monotonic() - start < 10
    time.sleep(0.5)  # a live writer would recreate the directory within one loop
    assert not watch.exists()


def test_timeout_kills_the_process_and_removes_the_directory(tmp_path):
    watch = tmp_path / "snap"
    watch.mkdir()
    (watch / "partial.bin").write_bytes(b"x")
    start = time.monotonic()
    with pytest.raises(IntakeError, match="timed out"):
        _run([sys.executable, "-c", LATE_WRITER, str(watch), "1.0"], watch, MB, 0.5)
    assert time.monotonic() - start < 5
    time.sleep(2.0)  # a surviving child would write late.txt about 1 s after it started
    assert not watch.exists()


def test_run_under_limit_that_exits_zero_keeps_the_directory(tmp_path):
    watch = tmp_path / "snap"
    script = """
import os, sys, time
time.sleep(0.5)  # the directory does not exist for the first polls, as at the start of a clone
os.makedirs(sys.argv[1])
with open(os.path.join(sys.argv[1], "hello.txt"), "w") as f:
    f.write("hi")
"""
    assert _run([sys.executable, "-c", script, str(watch)], watch, MB, 30) is None
    assert (watch / "hello.txt").read_text() == "hi"


def test_nonzero_exit_raises_clone_failed_and_removes_the_directory(tmp_path):
    watch = tmp_path / "snap"
    script = """
import os, sys
os.makedirs(sys.argv[1])
open(os.path.join(sys.argv[1], "partial.bin"), "w").close()
print("fatal: boom")
sys.exit(3)
"""
    with pytest.raises(IntakeError, match="Clone failed") as exc:
        _run([sys.executable, "-c", script, str(watch)], watch, MB, 30)
    assert "fatal: boom" in str(exc.value)
    assert not watch.exists()


def test_size_exactly_at_the_limit_does_not_trigger(tmp_path):
    watch = tmp_path / "snap"
    limit = 4096
    script = """
import os, sys, time
os.makedirs(sys.argv[1])
with open(os.path.join(sys.argv[1], "exact.bin"), "wb") as f:
    f.write(b"x" * int(sys.argv[2]))
time.sleep(1.0)  # stay alive across several polls while the size equals the limit
"""
    assert _run([sys.executable, "-c", script, str(watch), str(limit)], watch, limit, 30) is None
    assert (watch / "exact.bin").stat().st_size == limit


def test_file_vanishing_mid_walk_does_not_abort_the_clone(tmp_path, monkeypatch):
    # git renames temp packs while the watchdog walks the tree. The first poll fails, the next must still run.
    real_dir_size = intake._dir_size
    polls = []

    def flaky_dir_size(p):
        polls.append(p)
        if len(polls) == 1:
            raise FileNotFoundError("vanished mid-walk")
        return real_dir_size(p)

    monkeypatch.setattr(intake, "_dir_size", flaky_dir_size)
    watch = tmp_path / "snap"
    script = """
import os, sys, time
os.makedirs(sys.argv[1])
open(os.path.join(sys.argv[1], "pack.bin"), "w").close()
time.sleep(0.5)  # outlast the first poll interval, so the failing poll happens
"""
    assert _run([sys.executable, "-c", script, str(watch)], watch, MB, 30) is None
    assert polls


# git runs helpers (git-remote-https, index-pack) as children that write into the same directory.
# The grandchild below does not hold the output pipe, so a survivor would keep writing after the
# watchdog returns. It is bounded to 5 s, so a surviving copy cannot run forever.
HELPER_WRITER = """
import os, sys, time
for _ in range(100):
    os.makedirs(sys.argv[1], exist_ok=True)
    with open(os.path.join(sys.argv[1], "helper.bin"), "wb") as f:
        f.write(b"x")
    time.sleep(0.05)
"""


def test_processes_started_by_the_clone_are_killed_with_it(tmp_path):
    watch = tmp_path / "snap"
    parent = """
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", sys.argv[2], sys.argv[1]],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(5)
"""
    with pytest.raises(IntakeError, match="timed out"):
        _run([sys.executable, "-c", parent, str(watch), HELPER_WRITER], watch, MB, 0.5)
    time.sleep(1.5)
    assert not watch.exists()


def test_watchdog_does_not_wait_for_a_helper_that_holds_the_output_pipe(tmp_path):
    # Inherited stdout/stderr: the helper keeps the pipe open for 10 s, so an unkilled helper would
    # block the watchdog's final wait for that long.
    watch = tmp_path / "snap"
    parent = """
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
time.sleep(5)
"""
    start = time.monotonic()
    with pytest.raises(IntakeError, match="timed out"):
        _run([sys.executable, "-c", parent], watch, MB, 0.5)
    assert time.monotonic() - start < 5


def test_prepare_watches_the_clone_with_config_limits(monkeypatch):
    calls = []

    async def fake_run_watched(argv, watch_dir, max_bytes, timeout, env):
        calls.append((watch_dir, max_bytes, timeout))
        raise IntakeError("Clone failed (test)")

    monkeypatch.setattr(intake, "_run_watched", fake_run_watched)
    with pytest.raises(IntakeError, match="Clone failed"):
        asyncio.run(intake.prepare("limits_wiring", "https://github.com/octocat/Hello-World"))
    # While cloning, .git (the compressed pack) sits next to the checkout, so the watchdog sees up to ~1.7x the final
    # size (measured: flask 1.5x, requests 1.7x, numpy 1.3x). It gets 2x; the real limit is checked after .git is removed.
    assert calls == [(config.WORK_DIR / "limits_wiring" / "source",
                      2 * config.MAX_REPO_MB * 1024 * 1024, config.CLONE_TIMEOUT)]


def test_a_clone_whose_git_dir_pushes_it_past_the_limit_is_not_rejected_if_the_checkout_fits(monkeypatch):
    mb = 1024 * 1024
    monkeypatch.setattr(config, "MAX_REPO_MB", 4)

    async def fake_run_watched(argv, watch_dir, max_bytes, timeout, env):
        (watch_dir / ".git").mkdir(parents=True)
        (watch_dir / ".git" / "pack").write_bytes(b"x" * 2 * mb)  # compressed history
        (watch_dir / "code.bin").write_bytes(b"x" * 3 * mb)       # checkout: 3 MB final, 5 MB watched
        assert _watched_fits(watch_dir, max_bytes)

    def _watched_fits(d, limit):
        return intake._watched_size(d) <= limit

    async def fake_git(*args, cwd=None, timeout=30):
        return 0, "0123456789abcdef\n"

    monkeypatch.setattr(intake, "_run_watched", fake_run_watched)
    monkeypatch.setattr(intake, "_git", fake_git)
    info = asyncio.run(intake.prepare("limits_git_dir", "https://github.com/octocat/Hello-World"))
    assert info["commit_hash"] == "0123456789abcdef"
    intake.cleanup("limits_git_dir")


def test_prepare_removes_the_clone_when_the_post_clone_size_check_fails(monkeypatch):
    async def fake_run_watched(argv, watch_dir, max_bytes, timeout, env):
        watch_dir.mkdir(parents=True)
        (watch_dir / "big.bin").write_bytes(b"x")

    async def fake_git(*args, cwd=None, timeout=30):
        return 0, "0123456789abcdef\n"

    monkeypatch.setattr(intake, "_run_watched", fake_run_watched)
    monkeypatch.setattr(intake, "_git", fake_git)
    monkeypatch.setattr(config, "MAX_REPO_MB", 0)  # any byte is over the limit
    with pytest.raises(IntakeError, match="larger than"):
        asyncio.run(intake.prepare("limits_post", "https://github.com/octocat/Hello-World"))
    assert not (config.WORK_DIR / "limits_post" / "source").exists()


def test_a_checkout_over_the_limit_is_still_rejected_after_git_is_removed(monkeypatch):
    mb = 1024 * 1024
    monkeypatch.setattr(config, "MAX_REPO_MB", 4)

    async def fake_run_watched(argv, watch_dir, max_bytes, timeout, env):
        (watch_dir / ".git").mkdir(parents=True)
        (watch_dir / ".git" / "pack").write_bytes(b"x" * 2 * mb)
        (watch_dir / "code.bin").write_bytes(b"x" * 5 * mb)  # 5 MB checkout, 7 MB watched: under 2x8, over 4

    async def fake_git(*args, cwd=None, timeout=30):
        return 0, "0123456789abcdef\n"

    monkeypatch.setattr(intake, "_run_watched", fake_run_watched)
    monkeypatch.setattr(intake, "_git", fake_git)
    with pytest.raises(IntakeError, match="larger than 4 MB"):
        asyncio.run(intake.prepare("limits_over", "https://github.com/octocat/Hello-World"))
    assert not (config.WORK_DIR / "limits_over" / "source").exists()


def test_the_watchdog_abort_names_the_configured_limit_not_the_doubled_one(monkeypatch):
    monkeypatch.setattr(config, "MAX_REPO_MB", 50)

    async def fake_run_watched(argv, watch_dir, max_bytes, timeout, env):
        raise intake.RepoTooLarge("watchdog")

    monkeypatch.setattr(intake, "_run_watched", fake_run_watched)
    with pytest.raises(IntakeError) as exc:
        asyncio.run(intake.prepare("limits_msg", "https://github.com/octocat/Hello-World"))
    assert "larger than 50 MB" in str(exc.value) and "100" not in str(exc.value)


def test_watchdog_size_abort_is_a_repo_too_large_error(tmp_path):
    watch = tmp_path / "snap"
    with pytest.raises(intake.RepoTooLarge):
        _run([sys.executable, "-c", FLOOD, str(watch)], watch, 128 * 1024, 30)
