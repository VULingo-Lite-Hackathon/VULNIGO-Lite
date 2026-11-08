"""Failure paths of repository intake, up to a whole battle. Nothing here touches the network or Docker."""
import asyncio

import pytest

from vulnigo import battle, config, intake, llm, sandbox, store
from vulnigo.state import S

URL = "https://github.com/octocat/Hello-World"


@pytest.fixture(autouse=True)
def no_llm_no_sandbox(monkeypatch):
    monkeypatch.setattr(llm, "enabled", lambda: False)

    async def boom(*a, **k):
        raise AssertionError("the sandbox must not run when intake failed")
    monkeypatch.setattr(sandbox, "run", boom)


@pytest.mark.parametrize("raw,canonical", [
    ("https://GITHUB.COM/a/b", "https://github.com/a/b"),
    (" https://github.com/a/b\n", "https://github.com/a/b"),
    ("https://github.com/a/b/", "https://github.com/a/b"),
    ("https://github.com/a/b.git/", "https://github.com/a/b"),
    ("https://github.com:443/a/b", "https://github.com/a/b"),
    ("https://www.github.com/a/b", "https://github.com/a/b"),
    ("HTTPS://github.com/a/b", "https://github.com/a/b"),
])
def test_urls_are_cloned_in_one_canonical_form(raw, canonical):
    assert intake.validate_github_url(raw) == canonical


@pytest.mark.parametrize("raw", [
    "https://[::1]/a/b", "https://2130706433/a/b", "https://0x7f000001/a/b", "https://127.1/a/b",
    "https://github.com./a/b", "https://github.com\\@evil.com/a/b", "https://github.com%2f@evil.com/a/b",
    "https://github.com/%2e%2e/b", "https://github.com/a/%2e%2e", "https://gıthub.com/a/b",
    "https://github.com/a/b%0a", "https://github.com/a/b#x", "https://github.com/a/.git",
    "https://github.com/a/b\x00", "https://github.com/a/b\r\nHost: x", "https://github。com/a/b",
    "https://github.com/a/b/tree/main", "https://github.com/" + "a" * 300,
])
def test_hostile_urls_are_rejected(raw):
    with pytest.raises(intake.IntakeError):
        intake.validate_github_url(raw)


def test_a_bad_url_never_creates_a_run():
    before = {r["id"] for r in store.recent_runs(1000)}
    with pytest.raises(intake.IntakeError):
        battle.create("battle", "https://10.0.0.1/a/b", "spectator", None)
    assert {r["id"] for r in store.recent_runs(1000)} == before


@pytest.mark.parametrize("message", [
    "Clone failed (repo missing, private or unreachable): fatal: repository not found",
    "git clone timed out after 60s",
    "Repository is larger than 50 MB; Lite only supports small repos.",
])
def test_intake_failure_ends_the_battle_failed_and_clean(monkeypatch, message):
    async def failing(argv, watch_dir, max_bytes, timeout, env):
        watch_dir.mkdir(parents=True, exist_ok=True)
        (watch_dir / "half.bin").write_bytes(b"partial clone")
        intake._rm(watch_dir)  # what the real watchdog does before it raises
        raise intake.IntakeError(message)
    monkeypatch.setattr(intake, "_run_watched", failing)

    async def go():
        run = battle.create("battle", URL, "spectator", None)
        await asyncio.wait_for(run.task, 30)
        return run
    run = asyncio.run(go())
    assert run.state == S.FAILED
    errors = [e for e in store.list_for("events", run.id) if e["type"] == "error"]
    assert [e["message"] for e in errors] == [message]
    assert not store.list_for("test_runs", run.id)
    assert not [f for f in store.list_for("findings", run.id) if f["status"] == "confirmed"]
    assert not (config.WORK_DIR / run.id).exists()


def test_git_env_keeps_systemroot_when_the_host_has_it(monkeypatch):
    # Windows git cannot resolve DNS without SYSTEMROOT ("getaddrinfo() thread failed to start"); Linux has none.
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    assert intake._git_env()["SYSTEMROOT"] == r"C:\Windows"
    monkeypatch.delenv("SYSTEMROOT")
    assert "SYSTEMROOT" not in intake._git_env()


def test_git_env_passes_no_secrets(monkeypatch):
    monkeypatch.setenv("VULTR_API_KEY", "x")
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    assert not [k for k in intake._git_env() if "KEY" in k or "TOKEN" in k]
