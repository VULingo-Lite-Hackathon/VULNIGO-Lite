"""Need Backup -- summoning help for the side the human is actually playing.

A backup is not a fourth prompt and not a new kind of agent. It is the same Red or Blue
agent, seeded with the live finding, context and transcript so its first reply is useful.
That is why it costs a function instead of a workstream, and why it cannot do anything
the side it supports could not already do: there is no approval or apply path in here.

One backup per side per battle. A second press is refused rather than stacking agents, so
the claim "three agents plus one backup per side" stays true on screen.
"""

from dataclasses import dataclass, field

from .blue import BlueAgent
from .contract import FindingProposal, Side
from .inference import Inference
from .red import RedAgent


@dataclass
class BattleState:
    """Everything a helper needs to be useful from its first reply."""

    side: Side
    round_no: int = 1
    finding: FindingProposal | None = None
    context: str = ""
    transcript: list[str] = field(default_factory=list)
    evidence: str = ""

    def render(self) -> str:
        head = [
            f"Round {self.round_no}. You are joining as backup for the {self.side} side.",
            "The player is stuck. Pick up where they are; do not restart the analysis.",
        ]
        if self.finding:
            head.append(
                f"Active finding at {self.finding.location}: {self.finding.summary}\n"
                f"Data flow: {' -> '.join(self.finding.data_flow)}\n"
                f"Probe asked for: {self.finding.probe.probe_id} ({self.finding.proposal_id})"
            )
        if self.evidence:
            head.append(f"Recorded evidence:\n{self.evidence}")
        if self.transcript:
            head.append(
                "Conversation so far:\n" + "\n".join(f"- {line}" for line in self.transcript[-8:])
            )
        if self.context:
            head.append(f"Repository context already assembled ({len(self.context)} chars).")
        return "\n\n".join(head)


class BackupAlreadySummoned(RuntimeError):
    pass


class BackupRegistry:
    def __init__(self):
        self._active: dict[str, RedAgent | BlueAgent] = {}
        self.log: list[str] = []

    def summon(self, side: Side, inference: Inference, state: BattleState) -> RedAgent | BlueAgent:
        if side not in ("red", "blue"):
            raise ValueError(f"{side!r} is not a side a user can play")
        if side in self._active:
            raise BackupAlreadySummoned(
                f"the {side} backup is already working this battle; one per side"
            )
        agent: RedAgent | BlueAgent = RedAgent(inference) if side == "red" else BlueAgent(inference)
        brief = state.render()
        agent.seed(brief)
        agent.history.append(brief)
        self._active[side] = agent
        self.log.append(f"{side} backup summoned for round {state.round_no}")
        return agent

    def is_active(self, side: Side) -> bool:
        return side in self._active

    def active_sides(self) -> list[str]:
        return sorted(self._active)

    def summary(self) -> str:
        if not self.log:
            return "No backup was requested."
        return "; ".join(self.log)
