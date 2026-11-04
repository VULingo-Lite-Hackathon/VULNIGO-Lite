"""Blue Agent: root cause and the smallest reviewable patch. It cannot claim a fix."""

from dataclasses import dataclass

from .contract import FindingProposal, PatchProposal, diff_digest
from .inference import Inference, Usage
from .prompts import SYSTEM_BLUE, blue_task


@dataclass(frozen=True)
class BlueResult:
    patch: PatchProposal
    usage: Usage
    patch_id: str
    digest: str
    addresses_unconfirmed_finding: bool

    def describe(self) -> str:
        head = (
            f"Root cause: {self.patch.root_cause}\n"
            f"  files: {', '.join(self.patch.changed_files)}\n"
            f"  risks: {self.patch.risks}\n"
            f"  assumes: {self.patch.assumptions}"
        )
        if self.addresses_unconfirmed_finding:
            head += "\n  NOTE: the finding this patch answers was never reproduced by a test."
        return head


class BlueAgent:
    def __init__(self, inference: Inference, patch_id: str | None = None):
        self.inference = inference
        # Derived from the diff when not supplied: two different patches can never share
        # an id, so a stale approval cannot be pointed at a new diff.
        self.patch_id = patch_id
        self.history: list[str] = []
        self._seed = ""

    def seed(self, text: str) -> None:
        self._seed = text

    def explain(self, finding: FindingProposal, status: str, evidence: str) -> BlueResult:
        task = blue_task(finding, status, evidence)
        if self._seed:
            task = f"{self._seed}\n\n{task}"
        patch, usage = self.inference.ask("blue", SYSTEM_BLUE, task, PatchProposal)
        digest = diff_digest(patch.diff)
        return BlueResult(
            patch=patch,
            usage=usage,
            patch_id=self.patch_id or f"patch-{digest[:8]}",
            digest=digest,
            addresses_unconfirmed_finding=status != "confirmed",
        )
