"""The battle, in the phases a backend can actually drive.

A human approval gate sits in the middle of this loop, so no single function can own the
whole thing without blocking. `run_battle` is the convenience wrapper for tests and the
offline demo; the three phases below are what the HTTP layer should call, one per state
transition.

    run_attack       CREATED/SANDBOX_READY -> ATTACKING -> FINDINGS_REVIEW
    propose_defence  FINDINGS_REVIEW -> DEFENDING -> AWAITING_APPROVAL
    decide           PATCHING -> RETESTING -> COMPLETED / UNRESOLVED / INCONCLUSIVE

`decide` is pure: it takes the recorded retest and regression runs plus the approvals on
file and returns a verdict. Nothing in this module applies a patch, talks to Docker, or
writes to the store -- those belong to the sandbox and backend lanes.
"""

from dataclasses import dataclass, field
from typing import Callable

from .blue import BlueAgent, BlueResult
from .contract import (
    Approval,
    FindingProposal,
    PatchProposal,
    Pointer,
    RegressionRun,
    TestRun,
    classify_finding,
    patch_is_approved,
    retest_verdict,
)
from .inference import Inference, MODEL_FAILURES
from .manager import ManagerAgent
from .prompts import SourceFile
from .red import RedAgent, RedResult

ProbeRunner = Callable[[FindingProposal], TestRun]
RegressionRunner = Callable[[PatchProposal], list[RegressionRun]]
Approver = Callable[[BlueResult], Approval | None]


@dataclass
class Attack:
    """Round 1: a proposal, and what the recorded probes said about it."""

    result: RedResult
    status: str
    evidence: list[TestRun] = field(default_factory=list)
    reason: str = ""

    @property
    def proposal(self) -> FindingProposal:
        return self.result.proposal

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed"


@dataclass
class BattleOutcome:
    status: str = "unable_to_validate"
    verdict: str = "inconclusive"
    reason: str = "the battle did not run"
    proposal: FindingProposal | None = None
    patch: BlueResult | None = None
    applied: bool = False
    rounds: int = 0
    pointers: list[Pointer] = field(default_factory=list)
    dropped_pointers: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def headline(self) -> str:
        location = self.proposal.location if self.proposal else "no location"
        return f"{self.status} / {self.verdict} -- {location}. {self.reason}"


def run_attack(
    *,
    asker: Inference,
    files: list[SourceFile],
    commit: str,
    probe_runner: ProbeRunner,
    max_rounds: int = 2,
) -> Attack:
    """Ask Red, then let the recorded probe answer. Refine at most once more."""
    red = RedAgent(asker)
    snapshot = [(f.path, f.text.count("\n") + 1) for f in files]
    evidence: list[TestRun] = []
    result = red.propose(files, commit=commit)
    status = "unable_to_validate"

    for round_no in range(1, max(1, max_rounds) + 1):
        try:
            run = probe_runner(result.proposal)
        except MODEL_FAILURES + (OSError, TimeoutError) as exc:
            return Attack(
                result=result,
                status="unable_to_validate",
                evidence=evidence,
                reason=f"the probe could not run ({type(exc).__name__}); nothing was confirmed",
            )
        evidence.append(run)
        status = classify_finding(result.proposal, [run], files=snapshot)
        if status == "confirmed" or round_no >= max_rounds:
            break
        result = red.refine(
            files,
            commit=commit,
            feedback=(
                f"probe {run.probe_id} on {result.proposal.location} exited {run.exit_code}, "
                f"reproduced={run.reproduced}; output: {run.output_summary[:300]}"
            ),
        )

    reason = status if status == "confirmed" else f"{status}: no probe reproduced this hypothesis"
    return Attack(result=result, status=status, evidence=evidence, reason=reason)


def propose_defence(asker: Inference, attack: Attack) -> BlueResult:
    """Round 2. Blue sees the finding and the recorded evidence, never the whole snapshot."""
    blue = BlueAgent(asker)
    return blue.explain(attack.proposal, attack.status, evidence=describe_runs(attack.evidence))


def decide(
    attack: Attack,
    patch: BlueResult,
    *,
    approvals: list[Approval],
    retest: TestRun | None,
    regressions: list[RegressionRun],
    outcome: BattleOutcome | None = None,
) -> BattleOutcome:
    """Compute the verdict from what is on record. Applies nothing.

    Pass the caller's `outcome` when one already exists: this fills it in and returns the
    same object rather than replacing it, so nothing already recorded on it -- pointers,
    notes -- is silently dropped.
    """
    outcome = outcome if outcome is not None else BattleOutcome()
    outcome.status = attack.status
    outcome.proposal = attack.proposal
    outcome.patch = patch
    outcome.rounds = len(attack.evidence)
    for problem in attack.result.problems():
        if problem not in outcome.notes:
            outcome.notes.append(problem)

    outcome.applied = patch_is_approved(patch.patch_id, patch.digest, approvals)
    if not outcome.applied:
        outcome.verdict = "inconclusive"
        outcome.reason = "no approval record covers this exact diff, so nothing was applied or retested"
        return outcome

    outcome.verdict, outcome.reason = retest_verdict(attack.proposal, retest, regressions)
    return outcome


def run_battle(
    *,
    asker: Inference,
    files: list[SourceFile],
    commit: str,
    probe_runner: ProbeRunner,
    regression_runner: RegressionRunner | None = None,
    approvals: list[Approval] | None = None,
    approver: Approver | None = None,
    max_rounds: int = 2,
    spectate: bool = False,
) -> BattleOutcome:
    """The whole loop, for tests and the offline demo. A human gate is faked by `approver`."""
    approvals = list(approvals or [])
    outcome = BattleOutcome()

    try:
        attack = run_attack(
            asker=asker, files=files, commit=commit, probe_runner=probe_runner, max_rounds=max_rounds
        )
    except MODEL_FAILURES as exc:
        outcome.reason = f"the attacker model was unavailable ({type(exc).__name__})"
        return outcome

    outcome.status = attack.status
    outcome.proposal = attack.proposal
    outcome.rounds = len(attack.evidence)
    outcome.notes.extend(attack.result.problems())
    outcome.notes.append(f"attack: {attack.reason}")

    if spectate:
        _collect_pointers(outcome, asker, attack, None, [])

    if not attack.confirmed:
        outcome.reason = "the finding was never reproduced, so no patch was requested"
        return outcome

    try:
        patch = propose_defence(asker, attack)
    except MODEL_FAILURES as exc:
        outcome.verdict = "inconclusive"
        outcome.reason = f"the defender model was unavailable ({type(exc).__name__}); no patch was proposed"
        return outcome

    outcome.patch = patch
    if approver is not None:
        granted = approver(patch)
        if granted is not None:
            approvals.append(granted)

    retest = None
    regressions: list[RegressionRun] = []
    maybe_applied = patch_is_approved(patch.patch_id, patch.digest, approvals)
    if maybe_applied:
        try:
            retest = probe_runner(attack.proposal)
        except MODEL_FAILURES + (OSError, TimeoutError) as exc:
            retest = None
            outcome.notes.append(f"retest could not run: {type(exc).__name__}")
        if regression_runner is not None:
            regressions = regression_runner(patch.patch)

    decide(attack, patch, approvals=approvals, retest=retest, regressions=regressions, outcome=outcome)
    if not outcome.applied:
        outcome.notes.append("awaiting approval: the battle paused at AWAITING_APPROVAL")
    if spectate:
        _collect_pointers(outcome, asker, attack, patch, approvals)
    return outcome


def describe_runs(runs: list[TestRun]) -> str:
    return "\n".join(
        f"- {r.probe_id} ({r.run_id or 'unlabelled'}): exit {r.exit_code}, "
        f"reproduced={r.reproduced}, bound to {r.proposal_id or 'no hypothesis'}, {r.output_summary[:200]}"
        for r in runs
    )


def _collect_pointers(
    outcome: BattleOutcome,
    asker: Inference,
    attack: Attack,
    patch: BlueResult | None,
    approvals: list[Approval],
) -> None:
    manager = ManagerAgent(asker)
    ids = [run.run_id or f"run-{index + 1}" for index, run in enumerate(attack.evidence)]
    stages = [("attack", attack.proposal.summary)]
    if patch is not None:
        ids = ids + [patch.patch_id] + [a.subject_id for a in approvals]
        stages.append(("defense", f"Blue proposed {patch.patch_id}"))
        stages.append(("retest", f"verdict recorded as {outcome.verdict}"))

    done = {p.pointer_id for p in outcome.pointers} | {pid for pid, _ in outcome.dropped_pointers}

    for stage, event in stages:
        pointer_id = f"ptr-{stage.replace(' ', '-')}"
        if pointer_id in done:
            continue  # each stage is narrated once, even when the loop re-enters
        done.add(pointer_id)
        result = manager.pointer(pointer_id, f"{stage}: {event}", ids)
        if result.pointer is not None:
            outcome.pointers.append(result.pointer)
        elif result.reason:
            outcome.dropped_pointers.append((pointer_id, result.reason))
