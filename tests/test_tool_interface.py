import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

from vulnigo import scanner, sandbox

DEMO = Path(__file__).resolve().parent.parent / "demo_repo"
GOOD = {"file": "filedesk/tools.py", "function": "file_size", "param": "filename", "params": ["filename"],
        "token": "VGabc123", "category": "command-injection"}
CANNED = (0, 'VG_RESULT {"confirmed": true, "attempts": []}', False, False)


@pytest.fixture
def code_dir(tmp_path):
    d = tmp_path / "src"
    shutil.copytree(DEMO, d)
    return d


@pytest.fixture
def no_docker(monkeypatch):
    calls = []

    async def avail():
        return True

    async def boom(*a, **k):
        calls.append(a)
        raise AssertionError("docker reached")

    monkeypatch.setattr(sandbox, "docker_available", avail)
    monkeypatch.setattr(sandbox, "_exec", boom)
    return calls


@pytest.fixture
def fake_docker(monkeypatch):
    seen = []

    async def avail():
        return True

    async def fake(argv, env, cwd, timeout, kill_name):
        seen.append(argv)
        return CANNED

    monkeypatch.setattr(sandbox, "docker_available", avail)
    monkeypatch.setattr(sandbox, "_exec", fake)
    return seen


def run(action, code_dir, spec=None):
    return asyncio.run(sandbox.run("r1", action, str(code_dir), spec))


@pytest.mark.parametrize("action", ["shell", "../probe", "", "PROOF"])
def test_unknown_action(no_docker, code_dir, action):
    with pytest.raises(ValueError):
        run(action, code_dir, GOOD)


@pytest.mark.parametrize("action", ["proof", "benign"])
@pytest.mark.parametrize("bad", [
    {"file": "../x.py"}, {"file": "/etc/passwd.py"}, {"file": "builtins.py"}, {"file": "a\\b.py"},
    {"file": "pkg/../../x.py"}, {"file": "C:/x.py"}, {"file": "filedesk/tools.txt"}, {"file": "filedesk"},
    {"file": 5}, {"file": "nope/missing.py"},
    {"function": "__import__"}, {"function": "__init__"}, {"function": ""}, {"function": "a b"}, {"function": 3},
    {"param": "x; rm"}, {"param": 1},
    {"params": "filename"}, {"params": ["filename", "x; rm"]}, {"params": ["a", 1], "param": "a"},
    {"category": "sqli"}, {"token": "a;b"}, {"token": ""}, {"token": "A" * 65}, {"token": 5},
    {"custom_payload": 5}, {"custom_payload": "x" * 301},
    {"mode": "shell"}, {"cmd": "id"},
    {"function": "file_size\n"}, {"param": "filename\n", "params": ["filename\n"]}, {"token": "VGabc\n"},
])
def test_invalid_spec_rejected(no_docker, code_dir, action, bad):
    with pytest.raises(ValueError):
        run(action, code_dir, {**GOOD, **bad})
    assert no_docker == []


@pytest.mark.parametrize("missing", ["file", "function", "param", "params"])
def test_required_keys(no_docker, code_dir, missing):
    spec = {k: v for k, v in GOOD.items() if k != missing}
    with pytest.raises(ValueError):
        run("proof", code_dir, spec)


def test_none_spec_rejected(no_docker, code_dir):
    with pytest.raises(ValueError):
        run("proof", code_dir, None)


def test_symlink_escape(no_docker, code_dir, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n")
    try:
        os.symlink(outside, code_dir / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlink here")
    with pytest.raises(ValueError):
        run("proof", code_dir, {**GOOD, "file": "link.py"})


@pytest.mark.parametrize("action", ["proof", "benign"])
def test_valid_demo_spec(fake_docker, code_dir, action):
    row = run(action, code_dir, GOOD)
    assert row["kind"] == action and row["outcome"] in ("pass", "fail", "inconclusive")
    assert len(fake_docker) == 1


def test_valid_spec_with_metachar_payload(fake_docker, code_dir):
    payload = ("; rm -rf / $(id) `x` \n" * 20)[:300]
    row = run("proof", code_dir, {**GOOD, "custom_payload": payload})
    assert row["outcome"] == "pass"


def test_payload_only_inside_json_argv(fake_docker, code_dir):
    payload = "; rm -rf / $(id) `x` \n"
    run("proof", code_dir, {**GOOD, "custom_payload": payload})
    cmd = fake_docker[0]
    argv = cmd[cmd.index(sandbox.config.SANDBOX_IMAGE) + 1:]
    assert len(argv) == 3 and argv[:2] == ["python", "/harness/proof.py"]
    assert json.loads(argv[2])["custom_payload"] == payload
    assert sum(payload in a for a in cmd) == 0  # raw payload never an argv element (only JSON-escaped)


def test_probe_and_regression_unchanged(fake_docker, code_dir):
    assert run("probe", code_dir)["kind"] == "probe"
    assert run("regression", code_dir)["kind"] == "regression"


def test_every_scanner_candidate_validates(fake_docker):
    cands = scanner.scan_battle_candidates(DEMO)
    assert cands
    for c in cands:
        spec = {"file": c["file"], "function": c["function"], "param": c["param"], "params": c["params"],
                "category": c["category"], "token": "VG" + "ab12cd34ef56"}
        run("proof", DEMO, spec)
    assert len(fake_docker) == len(cands)


def test_private_function_is_accepted(fake_docker, code_dir):
    # proof.py handled it before validation existed; a real repo can have _helper().
    (code_dir / "helpers.py").write_text("def _helper(filename):\n    return filename\n")
    row = run("proof", code_dir, {**GOOD, "file": "helpers.py", "function": "_helper"})
    assert row["kind"] == "proof" and len(fake_docker) == 1


@pytest.mark.parametrize("name", ["os.py", "json.decoder.py", "a..b.py", "json/decoder.py", "sys.py"])
def test_file_that_proof_py_would_import_as_another_module_is_rejected(no_docker, code_dir, name):
    # proof.py turns file into a module name for importlib: these resolve to stdlib modules or a bogus dotted path,
    # not to the repo file that was checked, so a proof run on them proves nothing about the repo.
    target = code_dir / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("def system(command):\n    return command\n")
    with pytest.raises(ValueError):
        run("proof", code_dir, {**GOOD, "file": name, "function": "system", "param": "command", "params": ["command"]})
    assert no_docker == []


def test_scanner_candidates_with_unicode_name_and_keyword_only_param_validate(fake_docker, tmp_path):
    # The scanner takes names from ast: unicode identifiers and keyword-only params are real candidates.
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "m.py").write_text(
        "import subprocess\n\n\ndef f(a, *, cmd):\n    subprocess.run('ls ' + cmd, shell=True)\n\n\n"
        "def café(x):\n    subprocess.run('ls ' + x, shell=True)\n", encoding="utf-8")
    cands = scanner.scan_battle_candidates(tmp_path)
    assert {c["function"] for c in cands} == {"f", "café"}
    for c in cands:
        run("proof", tmp_path, {"file": c["file"], "function": c["function"], "param": c["param"],
                                "params": c["params"], "category": c["category"]})
    assert len(fake_docker) == 2
