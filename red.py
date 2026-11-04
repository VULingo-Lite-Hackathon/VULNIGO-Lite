"""Red Agent: proposes one finding and a bounded proof. It never decides its own status."""

from dataclasses import dataclass

from .contract import (
    VULNERABILITY_CLASS,
    FindingProposal,
    TestRun,
    classify_finding,
    grounding_problems,
)
from .inference import Inference, Usage
from .prompts import SourceFile, SYSTEM_RED, red_task, render_source_context


@dataclass(frozen=True)
class RedResult:
    proposal: FindingProposal
    usage: Usage
    context_truncated: bool
    files_offered: int
    snapshot: tuple[tuple[str, int], ...] = ()

    @property
    def in_scope(self) -> bool:
        return self.proposal.in_class

    def status(self, runs: list[TestRun]) -> str:
        return classify_finding(
            self.proposal, runs, files=list(self.snapshot) if self.snapshot else None
        )

    def problems(self) -> list[str]:
        """What a reviewer should be told about this proposal before any test runs."""
        out: list[str] = []
        if not self.in_scope:
            out.append(f"outside the frozen class ({self.proposal.vulnerability_class})")
        if self.snapshot:
            out.extend(grounding_problems(self.proposal, list(self.snapshot)))
        if self.context_truncated:
            out.append("the model was not shown the whole snapshot")
        return out

    def describe(self) -> str:
        note = "" if self.in_scope else f" [outside the frozen class: {self.proposal.vulnerability_class}]"
        return (
            f"{self.proposal.summary}{note}\n"
            f"  at {self.proposal.location}\n"
            f"  flow: {' -> '.join(self.proposal.data_flow)}\n"
            f"  probe: {self.proposal.probe.probe_id} -- {self.proposal.probe.purpose}\n"
            f"  expects: {self.proposal.probe.expected_signal}\n"
            f"  confidence {self.proposal.confidence:.2f}; limits: {self.proposal.limitations}"
        )


class RedAgent:
    def __init__(self, inference: Inference):
        self.inference = inference
        self.history: list[str] = []
        self._seed = ""

    def seed(self, text: str) -> None:
        """Context a backup agent is handed when it is summoned mid-battle."""
        self._seed = text

    def propose(self, files: list[SourceFile], commit: str) -> RedResult:
        context, truncated = render_source_context(files)
        task = self._prefixed(red_task(context, truncated, commit))
        proposal, usage = self.inference.ask("red", SYSTEM_RED, task, FindingProposal)
        return self._record(proposal, usage, truncated, files)

    def refine(self, files: list[SourceFile], commit: str, feedback: str) -> RedResult:
        """Called when the recorded probe did not support the proposal.

        The feedback is the test result, not an opinion, so the next proposal is
        corrected by evidence rather than by encouragement.
        """
        context, truncated = render_source_context(files)
        task = (
            f"{red_task(context, truncated, commit)}\n\n"
            "Your previous proposal was not supported by the recorded evidence.\n"
            f"{feedback}\n\n"
            "Propose again. Either correct the location, or correct the probe and say "
            "what you now expect to observe."
        )
        proposal, usage = self.inference.ask("red", SYSTEM_RED, self._prefixed(task), FindingProposal)
        return self._record(proposal, usage, truncated, files)

    def _prefixed(self, task: str) -> str:
        return f"{self._seed}\n\n{task}" if self._seed else task

    def _record(self, proposal, usage, truncated, files) -> RedResult:
        snapshot = tuple((f.path, f.text.count("\n") + 1) for f in files)
        result = RedResult(
            proposal=proposal,
            usage=usage,
            context_truncated=truncated,
            files_offered=len(files),
            snapshot=snapshot,
        )
        self.history.append(result.describe())
        return result
