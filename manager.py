"""Manager Agent: analyst and supervisor.

Split on purpose. Every *verdict* goes through a deterministic function in
`contract.py` -- the Manager model is never the security verifier for a battle, which is
what the requirements forbid. The model is used only for the two things that genuinely
need language: writing the Spectator's pointers, and reading a repository as a static
analyst.

Failures degrade instead of exploding: a lost pointer or a dead endpoint is recorded on
the object so the report can say the run was partial. A partial run presented as a
complete one is the failure mode this project exists to avoid.
"""

from dataclasses import dataclass, field

from .contract import (
    CheckItem,
    CheckItemDraft,
    FindingProposal,
    LineRange,
    Pointer,
    RegressionRun,
    RepoCheckReply,
    TestRun,
    classify_finding,
    makes_an_unsupported_claim,
    pointer_is_backed,
    render_check_summary,
    retest_verdict,
)
from .inference import Inference, MODEL_FAILURES
from .prompts import (
    SourceFile,
    SYSTEM_POINTER,
    SYSTEM_REPO_CHECK,
    pointer_task,
    render_source_context,
    repo_check_task,
)


@dataclass
class CheckOutcome:
    items: list[CheckItem] = field(default_factory=list)
    degraded: bool = False
    reason: str = ""

    @property
    def summary(self) -> str:
        base = render_check_summary(self.items)
        if self.degraded:
            return f"{base} PARTIAL RUN: {self.reason}."
        return base


@dataclass
class PointerOutcome:
    pointer: Pointer | None
    reason: str = ""


class ManagerAgent:
    def __init__(self, inference: Inference):
        self.inference = inference
        self.dropped_pointers: list[tuple[str, str]] = []

    # ---- verdicts: deterministic, no model in the path --------------------------

    @staticmethod
    def status_for(
        proposal: FindingProposal,
        runs: list[TestRun],
        files: list[tuple[str, int]] | None = None,
    ) -> str:
        return classify_finding(proposal, runs, files)

    @staticmethod
    def verdict_for(
        proposal: FindingProposal,
        retest: TestRun | None,
        regressions: list[RegressionRun],
    ) -> tuple[str, str]:
        return retest_verdict(proposal, retest, regressions)

    # ---- pointers: the Spectator's approval list --------------------------------

    def pointer(self, pointer_id: str, event: str, evidence_ids: list[str]) -> PointerOutcome:
        """Ask for one pointer; keep it only if it cites evidence we actually hold."""
        try:
            draft, _usage = self.inference.ask(
                "manager",
                SYSTEM_POINTER,
                pointer_task(pointer_id, event, evidence_ids),
                Pointer,
            )
        except MODEL_FAILURES as exc:
            reason = f"model failed: {type(exc).__name__}"
            self.dropped_pointers.append((pointer_id, reason))
            return PointerOutcome(None, reason)

        if draft.pointer_id != pointer_id:
            reason = "model changed the pointer id"
        elif not set(draft.evidence_ids) <= set(evidence_ids):
            reason = "cited evidence we do not hold"
        elif not pointer_is_backed(draft, set(evidence_ids)):
            reason = "no valid evidence reference"
        elif makes_an_unsupported_claim(draft.text):
            reason = "claimed a verdict no test recorded"
        else:
            return PointerOutcome(draft)

        self.dropped_pointers.append((pointer_id, reason))
        return PointerOutcome(None, reason)

    # ---- Repo Check: the Manager working alone ----------------------------------

    def repo_check(
        self, files: list[SourceFile], scanner_items: list[CheckItem], commit: str = "unknown"
    ) -> CheckOutcome:
        """Merge deterministic hits with the Manager's own reading.

        Anything the model produces is forced to `source="manager"` and stripped of a
        rule id. Without that override a model could write `source: "scanner"` and turn
        its own guess into a confirmed finding.
        """
        merged = list(scanner_items)
        context, truncated = render_source_context(files)
        known = [item.model_dump() for item in scanner_items]

        try:
            reply, _usage = self.inference.ask(
                "manager",
                SYSTEM_REPO_CHECK,
                repo_check_task(context, truncated, known),
                RepoCheckReply,
            )
        except MODEL_FAILURES as exc:
            return CheckOutcome(
                items=merged,
                degraded=True,
                reason=f"the analyst model was unavailable ({type(exc).__name__}); "
                "only the deterministic scanner results below are from this run",
            )

        for draft in reply.items:
            merged.append(
                CheckItem(
                    file_path=draft.file_path,
                    line=line_range(draft.line_start, draft.line_end),
                    indicator=draft.indicator,
                    rule_id=None,
                    source="manager",
                )
            )
        return CheckOutcome(items=_dedupe(merged))


def line_range(start: int | None, end: int | None) -> LineRange | None:
    if not start:
        return None
    return LineRange(start=start, end=end or start)


def _dedupe(items: list[CheckItem]) -> list[CheckItem]:
    seen: dict[str, CheckItem] = {}
    for item in items:
        key = f"{item.location}|{item.indicator[:60].lower()}"
        existing = seen.get(key)
        # A scanner hit outranks the model's paraphrase of the same line.
        if existing is None or (item.source == "scanner" and existing.source != "scanner"):
            seen[key] = item
    return list(seen.values())
