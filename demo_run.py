"""The whole battle loop, runnable with no key and no network.

    python -m agents.demo_run

Twenty-two checks, each one a claim the demo makes out loud: a finding only becomes
*confirmed* when a probe bound to that exact hypothesis reproduces it, an inconclusive
retest is never reported as fixed, a patch without an approval covering its exact bytes is
never applied, a model that invents a `confirmed` field is rejected, a second Need Backup
press is refused, a pointer citing evidence we do not hold or claiming a verdict no test
recorded is dropped, and a repository with nothing found is described as "nothing
detected", never as secure.

`CannedModel` stands in for the real client with the same `ask()` signature, so this
exercises the actual agent classes and the real `run_battle` loop rather than a parallel
pretend implementation.
"""

import json
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

from . import fixtures
from .backup import BackupAlreadySummoned, BackupRegistry, BattleState
from .battle import run_battle
from .contract import (
    CheckItemDraft,
    FindingProposal,
    Pointer,
    RepoCheckReply,
    classify_finding,
    diff_digest,
    patch_is_approved,
    render_check_summary,
    retest_verdict,
)
from .inference import BudgetExhausted, CallBudget, Usage
from .manager import ManagerAgent


class CannedModel:
    """Same call shape as agents.inference.Inference.ask; replies come from a queue."""

    def __init__(self, replies: dict[str, list[Any]]):
        self.queues = {role: list(items) for role, items in replies.items()}
        self.calls: list[str] = []
        self.seen_tasks: list[str] = []
        self.budget = CallBudget(999, 10**9)

    def ask(self, role: str, system: str, user: str, schema: type[BaseModel]):
        self.calls.append(role)
        self.seen_tasks.append(user)
        if not self.queues.get(role):
            raise AssertionError(f"no canned reply left for {role!r}")
        payload = self.queues[role].pop(0)
        if isinstance(payload, Exception):
            raise payload
        instance = payload if isinstance(payload, BaseModel) else schema.model_validate(payload)
        return instance, Usage(
            prompt_tokens=140, completion_tokens=60, elapsed_s=0.3, requested_model=role
        )


@dataclass
class Check:
    label: str
    ok: bool
    detail: str


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, label: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(label, ok, detail))

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def battle(
    *,
    probes: list[dict],
    approvals: list | None = None,
    approve: bool = False,
    spectate: bool = False,
    manager_replies: list[Any] | None = None,
):
    """Run one battle with canned agents and scripted probe outcomes."""
    queue = list(probes)
    planned = max(1, len(queue))
    model = CannedModel(
        {
            "red": [fixtures.proposal() for _ in range(planned)],
            "blue": [fixtures.patch()],
            "manager": list(manager_replies or []),
        }
    )

    def probe_runner(proposal):
        if not queue:
            raise AssertionError("probe_runner called more times than scripted")
        return fixtures.run_for(proposal, **queue.pop(0))

    def approver(patch):
        return fixtures.approval(patch.patch, subject_id=patch.patch_id)

    outcome = run_battle(
        asker=model,
        files=fixtures.sample_files(),
        commit="demo-4f2a19c",
        probe_runner=probe_runner,
        regression_runner=lambda patch: [fixtures.regression()],
        approvals=approvals or [],
        approver=approver if approve else None,
        max_rounds=planned,
        spectate=spectate,
    )
    return outcome, model


def rejected(payload: dict, model: type[BaseModel] = FindingProposal) -> str | None:
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        error = exc.errors()[0]
        return f"{error['type']}: {error['msg']}"
    return None


def run_checks() -> Report:
    report = Report()

    # 1 -- the full honest loop
    outcome, _model = battle(
        probes=[{}, {"reproduced": False, "output_summary": "marker absent after the patch"}],
        approve=True,
    )
    report.add(
        "confirmed finding -> approved patch -> retest fixed",
        outcome.status == "confirmed" and outcome.applied and outcome.verdict == "fixed",
        outcome.headline(),
    )

    # 2 -- a probe that does not reproduce leaves the finding a hypothesis
    outcome, model = battle(probes=[{"reproduced": False, "exit_code": 0}])
    report.add(
        "an unreproduced finding never becomes confirmed and never reaches patching",
        outcome.status == "unconfirmed" and "blue" not in model.calls,
        f"status={outcome.status} agent calls={model.calls}",
    )

    # 3 -- evidence must be bound to the hypothesis
    outcome, _model = battle(probes=[{}])
    unbound = fixtures.run(probe_id=outcome.proposal.probe_id)
    report.add(
        "a run that does not say which hypothesis it tested confirms nothing",
        classify_finding(outcome.proposal, [unbound], files=[("app.py", 14)]) == "unable_to_validate",
        f"run proposal_id={unbound.proposal_id!r}",
    )

    # 4/5/6 -- retest integrity, exercised straight through the verdict function
    target = fixtures.proposal()
    other = fixtures.proposal(file_path="api.py", line={"start": 4, "end": 5})
    cases = [
        ("a retest of a different probe cannot report fixed",
         fixtures.run_for(target, probe_id="regression-endpoint", reproduced=False)),
        ("a retest bound to another hypothesis cannot report fixed",
         fixtures.run_for(other, reproduced=False)),
        ("a crashed retest cannot report fixed",
         fixtures.run_for(target, reproduced=False, exit_code=7)),
        ("a timed-out retest cannot report fixed",
         fixtures.run_for(target, reproduced=False, timed_out=True)),
    ]
    for label, retest in cases:
        verdict, reason = retest_verdict(target, retest, [fixtures.regression()])
        report.add(label, verdict == "inconclusive", f"{verdict}: {reason}")

    # 7 -- no approval, no apply, no retest
    outcome, model = battle(probes=[{}, {"reproduced": False}])
    report.add(
        "a patch with no approval record is never applied or retested",
        not outcome.applied
        and outcome.verdict == "inconclusive"
        and "approval" in outcome.reason
        and model.calls.count("blue") == 1,
        outcome.reason,
    )

    # 8 -- an approval must cover the exact bytes
    first = fixtures.patch()
    second = fixtures.patch(diff=first.diff.replace("200x200", "400x400"))
    approval = fixtures.approval(first, subject_id="patch-x")
    report.add(
        "an approval for one diff does not vouch for a different diff with the same id",
        patch_is_approved("patch-x", diff_digest(second.diff), [approval]) is False
        and patch_is_approved("patch-x", diff_digest(first.diff), [approval]) is True,
        "digest mismatch blocks reuse",
    )

    # 9..13 -- schema-level refusals
    for label, payload, needle in (
        ("a model cannot declare its own finding confirmed", {"confirmed": True}, "extra_forbidden"),
        ("a summary cannot claim code is secure", {"summary": "The endpoint is secure and fixed"}, "value_error"),
        ("a probe outside the allowlist is refused",
         {"probe": {"probe_id": "curl-the-internet", "purpose": "x" * 20, "expected_signal": "y" * 20}},
         "not allowlisted"),
        ("a path that escapes the repository is refused", {"file_path": "../../etc/passwd"}, "escapes"),
        ("a filename with a quote or newline is refused", {"file_path": 'app".py\n'}, "unsafe in a path"),
    ):
        reason = rejected(fixtures.sample_proposal() | payload)
        report.add(label, reason is not None and needle in reason, reason or "ACCEPTED -- no guard")

    # 10b -- a finding outside the frozen class cannot be confirmed
    off = fixtures.proposal(vulnerability_class="path-traversal")
    report.add(
        "a finding outside the frozen vulnerability class is not confirmed",
        classify_finding(off, [fixtures.run_for(off)], files=[("app.py", 14)]) == "unable_to_validate",
        off.vulnerability_class,
    )

    # 14 -- Need Backup: one per side, and the seed really reaches the model
    registry = BackupRegistry()
    state = BattleState(side="red", round_no=2, finding=fixtures.proposal(),
                        transcript=["player cannot identify the sink"], evidence="exit 0, marker absent")
    spy = CannedModel({"red": [fixtures.proposal()]})
    agent = registry.summon("red", spy, state)
    agent.propose(fixtures.sample_files(), commit="demo")
    seeded = "You are joining as backup for the red side" in spy.seen_tasks[0]
    second_refused = False
    try:
        registry.summon("red", CannedModel({}), state)
    except BackupAlreadySummoned:
        second_refused = True
    report.add(
        "backup seeds the same agent with live state, and a second press is refused",
        seeded and second_refused,
        registry.summary(),
    )

    # 15/16 -- pointer discipline
    ghost = CannedModel({"manager": [Pointer(pointer_id="ptr-1", text="Red reproduced the marker at line 12",
                                            evidence_ids=["run-999"])]})
    dropped = ManagerAgent(ghost).pointer("ptr-1", "probe reproduced the marker", ["run-1"])
    claim = CannedModel({"manager": [Pointer(pointer_id="ptr-1", text="Blue fixed it; the repository is now secure",
                                            evidence_ids=["run-1"])]})
    claim_out = ManagerAgent(claim).pointer("ptr-1", "defense finished", ["run-1"])
    report.add("a pointer citing evidence we do not hold is dropped",
               dropped.pointer is None and "evidence" in dropped.reason, dropped.reason)
    report.add("a pointer claiming a verdict no test recorded is dropped",
               claim_out.pointer is None and "verdict" in claim_out.reason, claim_out.reason)

    # 17 -- Repo Check cannot be laundered, and degrades honestly
    launder = CannedModel({"manager": [RepoCheckReply(items=[CheckItemDraft(
        file_path="app.py", line_start=12, indicator="subprocess shell=True on request input",
        rule_id="python.fabricated.rule", source="scanner")])]})
    outcome_check = ManagerAgent(launder).repo_check(fixtures.sample_files(), scanner_items=[], commit="abc")
    down = CannedModel({"manager": [BudgetExhausted("token budget exhausted")]})
    degraded = ManagerAgent(down).repo_check(
        fixtures.sample_files(), scanner_items=[fixtures.scanner_item()], commit="abc"
    )
    report.add(
        "the analyst cannot launder its own guess into a scanner hit",
        all(i.source == "manager" and i.rule_id is None and i.status == "potential"
            for i in outcome_check.items),
        json.dumps([{"loc": i.location, "status": i.status} for i in outcome_check.items]),
    )
    report.add(
        "a dead analyst model degrades to a labelled partial run instead of failing silently",
        degraded.degraded and len(degraded.items) == 1 and "PARTIAL RUN" in degraded.summary,
        degraded.summary,
    )
    empty_summary = render_check_summary([])
    report.add(
        "a clean Repo Check says nothing was detected, never that a repo is safe",
        "secure" not in empty_summary.lower() and "safe" not in empty_summary.lower(),
        empty_summary,
    )

    # 22 -- Spectator mode narrates the battle without inventing verdicts
    from .contract import diff_digest as _dd

    pid = fixtures.proposal().proposal_id
    run_id = f"run-{pid[:6]}"
    patch_id = f"patch-{_dd(fixtures.patch().diff)[:8]}"
    narrated = [
        Pointer(pointer_id="ptr-attack", text="Red's probe reproduced the injection inside the sandbox",
                evidence_ids=[run_id]),
        Pointer(pointer_id="ptr-defense", text=f"Blue proposed {patch_id} to pass the filename as an argument",
                evidence_ids=[run_id, patch_id]),
        Pointer(pointer_id="ptr-retest", text="The original probe no longer reproduces and regression checks pass",
                evidence_ids=[run_id, patch_id]),
    ]
    outcome, model = battle(
        probes=[{}, {"reproduced": False, "output_summary": "marker absent after the patch"}],
        approve=True,
        spectate=True,
        manager_replies=narrated,
    )
    report.add(
        "spectator mode produces the pointer list a human approves",
        len(outcome.pointers) == 3 and not outcome.dropped_pointers and outcome.verdict == "fixed",
        f"{len(outcome.pointers)} pointers, {len(model.calls)} model calls, verdict={outcome.verdict}",
    )
    return report


def main() -> int:
    report = run_checks()
    print("VULNIGO Lite -- offline battle loop\n")
    for check in report.checks:
        print(f"  [{'PASS' if check.ok else 'FAIL'}] {check.label}")
        if check.detail:
            print(f"         {check.detail}")
    print(f"\n{len(report.checks) - len(report.failed)}/{len(report.checks)} checks held")
    for check in report.failed:
        print(f"  FAILED: {check.label} -- {check.detail}")
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
