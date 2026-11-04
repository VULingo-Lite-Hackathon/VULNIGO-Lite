"""Sample records and a fake vulnerable repository for the offline loop and the tests.

Nothing here is production behaviour: it exists so the battle loop can be exercised on a
laptop with no key, and so the tests describe the same shapes the reviewers read. The
vulnerable sample is illustrative only -- the demo repository is Ahmad's workstream.
"""

from .contract import (
    ALLOWED_PROBES,
    Approval,
    CheckItem,
    CheckItemDraft,
    FindingProposal,
    LineRange,
    PatchProposal,
    Pointer,
    RegressionRun,
    RepoCheckReply,
    TestRun,
    VULNERABILITY_CLASS,
    diff_digest,
)
from .prompts import SourceFile

VULNERABLE_SNIPPET = '''"""Tiny image-resizer demo. Intentionally vulnerable."""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/resize")
def resize():
    name = request.json["name"]
    # The filename comes straight off the wire into a shell string.
    out = subprocess.check_output(f"convert {name} -resize 200x200 out.png", shell=True)
    return {"bytes": len(out)}
'''

CLEAN_SNIPPET = VULNERABLE_SNIPPET.replace(
    'out = subprocess.check_output(f"convert {name} -resize 200x200 out.png", shell=True)',
    'out = subprocess.check_output(["convert", name, "-resize", "200x200", "out.png"])',
)


def sample_files(*, fixed: bool = False) -> list[SourceFile]:
    return [
        SourceFile(path="app.py", text=CLEAN_SNIPPET if fixed else VULNERABLE_SNIPPET),
        SourceFile(path="requirements.txt", text="flask==3.0.3\n"),
    ]


def sample_proposal(**overrides) -> dict:
    base = {
        "summary": "User-supplied filename reaches a shell string in the resize endpoint",
        "vulnerability_class": VULNERABILITY_CLASS,
        "file_path": "app.py",
        "line": {"start": 12, "end": 13},
        "data_flow": [
            "request.json['name'] is read from the POST body",
            "interpolated into the convert command string",
            "subprocess.check_output runs it with shell=True",
        ],
        "preconditions": "endpoint is reachable; no authentication in the demo app",
        "probe": {
            "probe_id": ALLOWED_PROBES[0],
            "purpose": "create a marker file through the shell metacharacters",
            "expected_signal": "marker exists inside the sandbox only",
        },
        "confidence": 0.7,
        "limitations": "static read only; no exploit attempted outside the sandbox",
    }
    base.update(overrides)
    return base


def proposal(**overrides) -> FindingProposal:
    return FindingProposal.model_validate(sample_proposal(**overrides))


def run_for(target: FindingProposal, **overrides) -> TestRun:
    """A run properly bound to the hypothesis it tested."""
    base = {
        "probe_id": target.probe.probe_id,
        "proposal_id": target.proposal_id,
        "run_id": f"run-{target.proposal_id[:6]}",
        "exit_code": 0,
        "reproduced": True,
        "environment_id": "sbx-demo-1",
        "output_summary": "marker file present after the probe ran",
        "elapsed_s": 2.4,
    }
    base.update(overrides)
    return TestRun.model_validate(base)


def run(**overrides) -> TestRun:
    """An unbound run -- useful for proving that unbound evidence confirms nothing."""
    base = {
        "probe_id": ALLOWED_PROBES[0],
        "exit_code": 0,
        "reproduced": True,
        "environment_id": "sbx-demo-1",
        "output_summary": "marker file present after the probe ran",
        "elapsed_s": 2.4,
    }
    base.update(overrides)
    return TestRun.model_validate(base)


def regression(name: str = "resize-still-works", **overrides) -> RegressionRun:
    base = {"name": name, "passed": True, "timed_out": False}
    base.update(overrides)
    return RegressionRun.model_validate(base)


def patch(**overrides) -> PatchProposal:
    base = {
        "root_cause": "the filename is interpolated into a shell command instead of passed as an argument",
        "diff": (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -9,5 +9,5 @@\n"
            '-    out = subprocess.check_output(f"convert {name} -resize 200x200 out.png", shell=True)\n'
            '+    out = subprocess.check_output(["convert", name, "-resize", "200x200", "out.png"])\n'
        ),
        "changed_files": ["app.py"],
        "risks": "shell features stop working by design; callers relying on them must change",
        "assumptions": "convert is on PATH and no caller depends on shell expansion",
    }
    base.update(overrides)
    return PatchProposal.model_validate(base)


def approval(target: PatchProposal | None = None, **overrides) -> Approval:
    target = target or patch()
    base = {
        "subject_type": "patch",
        "subject_id": overrides.pop("subject_id", "patch-1"),
        "subject_digest": diff_digest(target.diff),
        "granted": True,
        "decided_by": "ishaan",
        "note": "read the diff line by line before approving",
    }
    base.update(overrides)
    return Approval.model_validate(base)


def pointer(pointer_id: str = "ptr-1", **overrides) -> Pointer:
    base = {
        "pointer_id": pointer_id,
        "text": "Red reproduced the injection; the marker appeared inside the sandbox only",
        "evidence_ids": ["run-1"],
    }
    base.update(overrides)
    return Pointer.model_validate(base)


def scanner_item(**overrides) -> CheckItem:
    base = {
        "file_path": "app.py",
        "line": LineRange(start=12, end=13),
        "indicator": "subprocess with shell=True on request input",
        "rule_id": "python.lang.security.audit.subprocess-shell-true",
        "source": "scanner",
    }
    base.update(overrides)
    return CheckItem.model_validate(base)


def repo_draft(**overrides) -> CheckItemDraft:
    base = {
        "file_path": "settings.py",
        "line_start": 7,
        "indicator": "installs a wheel from a host that does not exist yet",
        "rule_id": None,
        "source": "manager",
    }
    base.update(overrides)
    return CheckItemDraft.model_validate(base)


def repo_reply(*items: CheckItemDraft) -> RepoCheckReply:
    return RepoCheckReply(items=list(items))
