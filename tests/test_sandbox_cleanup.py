"""Container cleanup and the container cap. A fake `docker` stands in, so no Docker is needed."""
import asyncio
import datetime
import shutil
import sys
from pathlib import Path

import pytest

from vulnigo import sandbox

DEMO = Path(__file__).resolve().parent.parent / "demo_repo"


def _ago(seconds: float) -> str:
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


class FakeDocker:
    """`ages` maps container name -> seconds since it was created (what `docker inspect` reports)."""

    def __init__(self, listing="", fail=(), ages=None):
        self.calls, self.listing, self.fail, self.ages = [], listing, set(fail), ages or {}

    async def __call__(self, *args, timeout=sandbox.KILL_TIMEOUT_S):
        self.calls.append(args)
        if args[0] in self.fail:
            return None, ""  # timed out
        if args[0] == "ps":
            return 0, self.listing
        if args[0] == "inspect":
            return 0, "".join(f"/{n} {_ago(self.ages.get(n, 9999))}\n" for n in args[3:])
        return 0, ""


@pytest.fixture
def docker(monkeypatch):
    d = FakeDocker()
    monkeypatch.setattr(sandbox, "_docker", d)
    return d


class FakeProc:
    async def wait(self):
        return 0

    def kill(self):
        pass


def test_sweep_removes_only_stale_sandbox_containers(docker):
    docker.listing = "sbx_0123abcd\nmy-postgres\nsbx_ffffffff\nsbx_evil;rm\nsbx_0123abcd2\nsbx_00000001\n"
    # sbx_00000001 is another process's run that started 2 s ago: not ours to remove
    docker.ages = {"sbx_0123abcd": 9999, "sbx_ffffffff": 9999, "sbx_00000001": 2}
    assert asyncio.run(sandbox.sweep_leftovers()) == 2
    assert [c for c in docker.calls if c[0] == "rm"] == [("rm", "-f", "sbx_0123abcd"), ("rm", "-f", "sbx_ffffffff")]


def test_sweep_with_nothing_left_removes_nothing(docker):
    assert asyncio.run(sandbox.sweep_leftovers()) == 0
    assert not [c for c in docker.calls if c[0] == "rm"]


def test_sweep_survives_a_docker_that_does_not_answer(docker):
    docker.fail = {"ps"}
    assert asyncio.run(sandbox.sweep_leftovers()) == 0


def test_kill_falls_back_to_rm_when_docker_kill_times_out(docker):
    docker.fail = {"kill"}
    asyncio.run(sandbox._kill(FakeProc(), "sbx_0123abcd"))
    assert ("rm", "-f", "sbx_0123abcd") in docker.calls


def test_kill_does_not_rm_when_docker_kill_worked(docker):
    asyncio.run(sandbox._kill(FakeProc(), "sbx_0123abcd"))
    assert not [c for c in docker.calls if c[0] == "rm"]


@pytest.fixture
def code_dir(tmp_path):
    d = tmp_path / "src"
    shutil.copytree(DEMO, d)
    return d


def _patch_run(monkeypatch, state, hold=0.05):
    async def avail():
        return True

    async def fake(argv, env, cwd, timeout, kill_name):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(hold)
        state["now"] -= 1
        return 0, 'VG_RESULT {"confirmed": true, "attempts": []}', False, False

    async def noop():
        return 0

    monkeypatch.setattr(sandbox, "docker_available", avail)
    monkeypatch.setattr(sandbox, "_exec", fake)
    monkeypatch.setattr(sandbox, "sweep_leftovers", noop)


def _sweep_on(monkeypatch):
    monkeypatch.setattr(sandbox, "_swept", False)
    monkeypatch.setattr(sandbox, "_sweeping", None)


def test_no_more_containers_than_the_cap_run_at_once(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)
    monkeypatch.setattr(sandbox, "MAX_CONTAINERS", 2)

    async def go():
        await asyncio.gather(*[sandbox.run("r", "probe", str(code_dir)) for _ in range(8)])
    asyncio.run(go())
    assert state["peak"] == 2


def test_waiting_for_a_slot_does_not_eat_the_test_timeout(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)
    monkeypatch.setattr(sandbox, "MAX_CONTAINERS", 1)
    seen = []
    orig = sandbox._exec

    async def spy(argv, env, cwd, timeout, kill_name):
        seen.append(timeout)
        return await orig(argv, env, cwd, timeout, kill_name)
    monkeypatch.setattr(sandbox, "_exec", spy)

    async def go():
        await asyncio.gather(*[sandbox.run("r", "probe", str(code_dir)) for _ in range(3)])
    asyncio.run(go())
    assert set(seen) == {sandbox.config.SANDBOX_TIMEOUT + 10}


def test_first_run_sweeps_leftovers_once(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)
    swept = []

    async def sweep():
        swept.append(1)
        return 0
    monkeypatch.setattr(sandbox, "sweep_leftovers", sweep)
    _sweep_on(monkeypatch)

    async def go():
        await asyncio.gather(*[sandbox.run("r", "probe", str(code_dir)) for _ in range(4)])
    asyncio.run(go())
    assert swept == [1]


def test_no_container_starts_before_the_sweep_has_finished(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)
    order = []

    async def sweep():
        order.append("sweep start")
        await asyncio.sleep(0.1)
        order.append("sweep end")
        return 0
    orig = sandbox._exec

    async def spy(*a):
        order.append("container")
        return await orig(*a)
    monkeypatch.setattr(sandbox, "sweep_leftovers", sweep)
    monkeypatch.setattr(sandbox, "_exec", spy)
    _sweep_on(monkeypatch)

    async def go():
        await asyncio.gather(*[sandbox.run("r", "probe", str(code_dir)) for _ in range(3)])
    asyncio.run(go())
    assert order[:2] == ["sweep start", "sweep end"] and order.count("container") == 3


def test_a_cancelled_first_run_does_not_break_the_runs_after_it(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)
    done = []

    async def slow_sweep():
        await asyncio.sleep(0.3)
        done.append(1)
        return 0
    monkeypatch.setattr(sandbox, "sweep_leftovers", slow_sweep)
    _sweep_on(monkeypatch)

    async def go():
        first = asyncio.ensure_future(sandbox.run("r", "probe", str(code_dir)))
        await asyncio.sleep(0.05)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        return await sandbox.run("r", "probe", str(code_dir))
    assert asyncio.run(go())["kind"] == "probe"
    assert done == [1]


def test_a_sweep_that_raises_does_not_block_runs(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)

    async def broken():
        raise RuntimeError("docker exploded")
    monkeypatch.setattr(sandbox, "sweep_leftovers", broken)
    _sweep_on(monkeypatch)
    assert asyncio.run(sandbox.run("r", "probe", str(code_dir)))["kind"] == "probe"


def test_a_cancelled_run_kills_its_container(docker):
    argv = [sys.executable, "-c", "import time; time.sleep(60)"]

    async def go():
        t = asyncio.ensure_future(sandbox._exec(argv, None, None, 60, "sbx_0123abcd"))
        await asyncio.sleep(0.5)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    asyncio.run(go())
    assert ("kill", "sbx_0123abcd") in docker.calls


def test_a_sweep_left_pending_by_a_finished_event_loop_does_not_break_the_next_loop(monkeypatch, code_dir):
    state = {"now": 0, "peak": 0}
    _patch_run(monkeypatch, state)

    async def slow_sweep():
        await asyncio.sleep(5)
        return 0
    monkeypatch.setattr(sandbox, "sweep_leftovers", slow_sweep)
    _sweep_on(monkeypatch)
    with pytest.raises(asyncio.TimeoutError):  # asyncio.run ends this loop with the sweep still pending
        asyncio.run(asyncio.wait_for(sandbox.run("r", "probe", str(code_dir)), 0.2))

    async def quick_sweep():
        return 0
    monkeypatch.setattr(sandbox, "sweep_leftovers", quick_sweep)
    assert asyncio.run(sandbox.run("r", "probe", str(code_dir)))["kind"] == "probe"


def test_a_new_event_loop_does_not_drop_another_loops_semaphore():
    loops = [asyncio.new_event_loop(), asyncio.new_event_loop()]
    try:
        async def get():
            return sandbox._slot()
        first = loops[0].run_until_complete(get())
        loops[1].run_until_complete(get())
        assert loops[0].run_until_complete(get()) is first
    finally:
        for lp in loops:
            lp.close()
