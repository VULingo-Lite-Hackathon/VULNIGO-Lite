"""CWE-22 path traversal: scanner, deterministic fix, the real proof harness and a full battle."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from vulnigo import battle, patcher, scanner, store
from vulnigo.state import S

from test_core import DEMO, _approve_when_ready, fake_sandbox  # noqa: F401  (fixture re-export)

HARNESS = Path(__file__).resolve().parents[1] / "vulnigo" / "harness" / "proof.py"


def _pt(root):
    return scanner.scan_path_traversal(Path(root))


def test_scanner_finds_planted_traversal():
    found = _pt(DEMO)
    assert [(f["file"], f["function"], f["param"], f["line_start"]) for f in found] == \
        [("filedesk/tools.py", "read_upload", "filename", 20)]
    assert found[0]["cwe"] == "CWE-22"


def test_battle_candidates_put_command_injection_first():
    cats = [c["category"] for c in scanner.scan_battle_candidates(DEMO)]
    assert cats == ["command-injection", "path-traversal"]


def test_scanner_ignores_sanitised_and_write_paths(tmp_path):
    (tmp_path / "m.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "def a(name):\n    name = os.path.basename(name)\n    return open(os.path.join('u', name)).read()\n"
        "def b(name):\n    return (Path('u') / Path(name).name).read_text()\n"
        "def c(name):\n    open(os.path.join('u', name), 'w').write('x')\n"
        "def d(name):\n    if os.path.basename(name) != name:\n        raise ValueError\n    return open(name).read()\n"
        "def e():\n    return open('fixed.txt').read()\n"
        "def f(name):\n    return (Path('u') / name).read_text()\n")
    assert [x["function"] for x in _pt(tmp_path)] == ["f"]


def _patched_copy(tmp_path, finding):
    work = tmp_path / "work"
    shutil.copytree(DEMO, work)
    fix = patcher.deterministic_fix(str(work), finding)
    (work / finding["file"]).write_text(fix["new_text"], encoding="utf-8")
    return work, fix


def test_deterministic_fix_adds_guard_and_clears_scanner(tmp_path):
    f = _pt(DEMO)[0]
    work, fix = _patched_copy(tmp_path, f)
    assert "os.path.basename(filename) != filename" in fix["new_text"]
    assert fix["new_text"].count("import os") == 1
    assert "shell=True" in fix["new_text"]  # the other planted bug is untouched: one fix per finding
    assert _pt(work) == []


def _proof(src: Path, tmp: Path, spec: dict) -> dict:
    env = {**os.environ, "VG_SRC": str(src), "VG_TMP": str(tmp)}
    out = subprocess.run([sys.executable, str(HARNESS), json.dumps(spec)], env=env, capture_output=True,
                         text=True, timeout=60).stdout
    return json.loads(next(l for l in out.splitlines() if l.startswith("VG_RESULT "))[len("VG_RESULT "):])


def test_real_harness_reproduces_then_patch_blocks_it(tmp_path):
    f = _pt(DEMO)[0]
    spec = {"file": f["file"], "function": f["function"], "param": f["param"], "params": f["params"],
            "category": "path-traversal", "token": "VGtesttoken01"}
    before = _proof(DEMO, tmp_path / "t1", spec)
    assert before["confirmed"] is True
    assert any("VGtesttoken01" in a.get("leaked", "") for a in before["attempts"])

    work, _ = _patched_copy(tmp_path, f)
    after = _proof(work, tmp_path / "t2", {**spec, "token": "VGtesttoken02"})
    assert after["confirmed"] is False and len(after["attempts"]) >= 4
    assert all("ValueError" in a.get("exception", "") for a in after["attempts"])
    benign = _proof(work, tmp_path / "t3", {**spec, "mode": "benign"})
    assert benign["benign"]["ok"] is True and "vulnigo sample" in benign["benign"]["return"]


def test_red_participant_picks_traversal_and_blue_fixes_it(fake_sandbox):  # noqa: F811
    async def go():
        run = battle.create("battle", None, "participate", "red")
        for _ in range(200):
            if run.waiting == "red_attack":
                break
            await asyncio.sleep(0.02)
        battle.submit_human(run, {"candidate_index": 1, "hypothesis": "preview reads any file"})
        await _approve_when_ready(run)
        for _ in range(200):
            if run.waiting == "red_retest":
                battle.submit_human(run, {"proceed": True})
                break
            if run.task.done():
                break
            await asyncio.sleep(0.02)
        await run.task
        return run
    run = asyncio.run(go())
    assert run.state == S.COMPLETED
    f = store.list_for("findings", run.id)[0]
    assert f["category"] == "path-traversal" and f["function"] == "read_upload" and f["status"] == "fixed"
    assert "read_upload" in f["hypothesis"] and "file_size" not in f["hypothesis"]
    assert "os.path.basename(filename)" in store.list_for("patches", run.id)[0]["diff"]
