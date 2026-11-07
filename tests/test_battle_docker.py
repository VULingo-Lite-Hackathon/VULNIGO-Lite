"""Whole battles against the real Docker sandbox (no fake sandbox). Skipped without Docker and the image.

Run only these:  pytest tests/test_battle_docker.py -m docker
"""
import asyncio
import subprocess
import time

import pytest

from vulnigo import battle, llm, sandbox, scanner, store
from vulnigo.state import S, TERMINAL

pytestmark = pytest.mark.docker


def _docker_ready() -> bool:
    try:
        return asyncio.run(sandbox.docker_available())
    except Exception:
        return False


if not _docker_ready():
    pytest.skip("needs a Docker daemon and the vulnigo-sandbox:latest image", allow_module_level=True)


@pytest.fixture(autouse=True)
def no_llm(monkeypatch):
    monkeypatch.setattr(llm, "enabled", lambda: False)


def sandbox_containers() -> list[str]:
    left = []
    for _ in range(10):
        left = subprocess.run(["docker", "ps", "-a", "--filter", "name=sbx_", "--format", "{{.Names}}"],
                              capture_output=True, text=True).stdout.split()
        if not left:
            break
        time.sleep(0.5)
    return left


async def _approve_when_ready(run, decision="approved"):
    for _ in range(1500):
        if run.waiting == "approval":
            battle.submit_approval(run, run.patch_id, decision, "test")
            return
        if run.state in TERMINAL:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("never reached approval")


def test_full_demo_battle_runs_in_real_docker():
    async def go():
        run = battle.create("battle", None, "spectator", None)
        await _approve_when_ready(run)
        await asyncio.wait_for(run.task, 300)
        return run
    run = asyncio.run(go())
    assert run.state in TERMINAL
    rows = store.list_for("test_runs", run.id)
    assert {"probe", "proof", "benign", "regression"} <= {r["kind"] for r in rows}
    assert all(r["sandboxed"] == 1 for r in rows)
    assert not any("Sandbox unavailable" in (r["output"] or "") for r in rows)
    probe = next(r for r in rows if r["kind"] == "probe")
    assert probe["outcome"] == "pass", probe["output"][-300:]  # every escape attempt blocked
    retest = [r for r in rows if (r["data"] or {}).get("label") == "retest proof"]
    assert len(retest) == 1 and retest[0]["outcome"] in ("pass", "fail", "inconclusive")
    assert run.state == S.COMPLETED and retest[0]["outcome"] == "fail"  # fix held: proof no longer reproduces
    assert sandbox_containers() == []


def test_a_candidate_with_an_invalid_spec_fails_the_run_honestly(monkeypatch):
    real = scanner.scan_battle_candidates

    def evil(root):
        return [{**c, "file": "../../etc/passwd.py"} for c in real(root)][:1]

    monkeypatch.setattr(scanner, "scan_battle_candidates", evil)

    async def go():
        run = battle.create("battle", None, "spectator", None)
        await asyncio.wait_for(run.task, 60)
        return run
    run = asyncio.run(go())
    assert run.state in (S.FAILED, S.ATTACK_INCONCLUSIVE)
    assert any(e["type"] == "error" for e in store.list_for("events", run.id))
    assert not [f for f in store.list_for("findings", run.id) if f["status"] == "confirmed"]
    assert not [p for p in store.list_for("patches", run.id) if p["approval_status"] == "approved" or p.get("applied_hash")]
    assert not [t for t in store.list_for("test_runs", run.id) if t["kind"] == "proof"]
    assert sandbox_containers() == []
