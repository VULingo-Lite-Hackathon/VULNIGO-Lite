"""Output cap: a sandboxed program that floods stdout must not fill the backend's memory.

These tests use a plain Python subprocess as a stand-in for the `docker run` client, so they need no Docker.
"""
import asyncio
import sys
import time

from vulnigo import sandbox

FLOOD_FOREVER = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n    sys.stdout.flush()\n"


def run_exec(code: str, timeout: int = 10):
    argv = [sys.executable, "-c", code]
    return asyncio.run(sandbox._exec(argv, None, None, timeout, None))


def test_endless_output_is_cut_at_the_cap_and_returns_quickly():
    started = time.monotonic()
    code, out, timed_out, truncated = run_exec(FLOOD_FOREVER)
    assert truncated is True
    assert timed_out is False
    assert len(out.encode()) <= sandbox.MAX_OUTPUT_BYTES + 200  # cap plus the notice line
    assert time.monotonic() - started < 5  # the timeout is 10 s: it was cut by the cap, not by the clock


def test_one_megabyte_of_output_never_reaches_the_caller_whole():
    # Absolute bound, not tied to the constant: whatever the cap is, 1 MB must not get through.
    code, out, timed_out, truncated = run_exec("import sys; sys.stdout.write('z' * 1_000_000)")
    assert truncated is True
    assert len(out.encode()) <= 100 * 1024


def test_output_just_under_the_cap_is_kept_whole():
    n = sandbox.MAX_OUTPUT_BYTES - 1
    code, out, timed_out, truncated = run_exec(f"import sys; sys.stdout.write('y' * {n})")
    assert truncated is False
    assert code == 0
    assert out == "y" * n


def test_output_exactly_at_the_cap_is_kept_whole():
    n = sandbox.MAX_OUTPUT_BYTES
    code, out, timed_out, truncated = run_exec(f"import sys; sys.stdout.write('y' * {n})")
    assert truncated is False
    assert out == "y" * n


def test_output_over_the_cap_by_one_byte_is_truncated():
    n = sandbox.MAX_OUTPUT_BYTES + 1
    code, out, timed_out, truncated = run_exec(f"import sys; sys.stdout.write('y' * {n})")
    assert truncated is True
    assert out.startswith("y" * sandbox.MAX_OUTPUT_BYTES)


def test_timeout_still_works_when_there_is_no_output():
    code, out, timed_out, truncated = run_exec("import time; time.sleep(30)", timeout=1)
    assert timed_out is True
    assert truncated is False
    assert code is None


def test_truncated_run_is_never_a_pass():
    # Output that was cut can hold a forged or half-written result line. Never trust it.
    forged = 'VG_RESULT {"confirmed": true, "all_blocked": true}'
    parsed = sandbox._parse(forged)
    for action in ("proof", "probe", "benign", "regression"):
        assert sandbox._outcome(action, 0, forged, parsed, False, truncated=True) == "inconclusive"


def test_the_program_is_killed_when_the_cap_is_hit(tmp_path):
    beat = tmp_path / "beat.txt"
    code = "\n".join([
        "import sys, time",
        f"sys.stdout.write('x' * {sandbox.MAX_OUTPUT_BYTES + 1000}); sys.stdout.flush()",
        "while True:",
        f"    open({str(beat)!r}, 'a').write('.')",
        "    time.sleep(0.05)",
    ])
    code_, out, timed_out, truncated = run_exec(code)
    assert truncated is True
    time.sleep(0.3)
    size = beat.stat().st_size if beat.exists() else 0
    time.sleep(0.6)
    after = beat.stat().st_size if beat.exists() else 0
    assert after == size, "the program kept running after the cap was hit"
