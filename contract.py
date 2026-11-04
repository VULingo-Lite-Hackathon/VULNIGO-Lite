"""The shared data shapes every workstream builds against.

Three structural decisions, all deliberate:

* **No agent can say "confirmed" or "fixed".** The Red and Blue schemas have no field
  for it, and `extra="forbid"` means an invented one fails validation instead of being
  quietly stored. Status is computed by `classify_finding` and `retest_verdict` from
  recorded probe runs.
* **Evidence is bound to the hypothesis it tested.** Every proposal carries a digest and
  every run echoes it, so a run recorded against an earlier idea cannot confirm a later
  one, and an approval cannot vouch for a different diff that happens to share an id.
* **Missing or contradictory evidence is `unable_to_validate`, never a verdict.** Being
  under-claiming on purpose is the product.

File paths and lengths are bounded because repository code is untrusted input, its text
is shown to humans, and its filenames come back into our own prompts.
"""

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Side = Literal["red", "blue"]
FindingStatus = Literal["confirmed", "unconfirmed", "unable_to_validate"]
CheckStatus = Literal["confirmed", "potential", "inconclusive"]
RetestStatus = Literal["fixed", "unresolved", "inconclusive"]

VULNERABILITY_CLASS = "command-injection"

# The only probes a model may ask for. Anything else has to be added here first, by a
# human, and shipped in sandbox/probes/ -- this is the allowlisted tool interface.
ALLOWED_PROBES = (
    "command-injection-proof",
    "regression-endpoint",
    "selftest",
)

# A heuristic, not a proof: it blocks the confident-sounding replies that review actually
# found, and every pointer remains bounded by the evidence ids it must cite. The verdict
# itself never comes from here -- it comes from a recorded TestRun.
CLAIM_WORDS = re.compile(
    r"\b(secure|safe|fixed|fully fixed|clean|verified|no issues|cannot be exploited|"
    r"unexploitable|hardened|all clear|watertight|bulletproof)\b|no longer vulnerable",
    re.IGNORECASE,
)

MAX_LINE_SPAN = 400
_UNSAFE_PATH_CHARS = re.compile(r'["\'\\<>|:*?\x00-\x1f]')

# Refuse anything that could carry an ANSI escape, a NUL or a stray CR. Single-line fields
# also refuse newlines, so one stored string cannot become two log records.
_MULTILINE_JUNK = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ONE_LINE_JUNK = re.compile(r"[\x00-\x1f\x7f]")


def printable(value: str, field: str, *, single_line: bool = True) -> str:
    if (_ONE_LINE_JUNK if single_line else _MULTILINE_JUNK).search(value):
        raise ValueError(f"{field} contains control characters")
    return value


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def safe_relative_path(value: str, field: str) -> str:
    raw = value.strip().replace("\\", "/")
    problems = []
    if not raw:
        problems.append("empty")
    if raw.startswith("/"):
        problems.append("absolute")
    if len(raw) > 2 and raw[1] == ":":
        problems.append("drive-qualified")
    if raw.startswith("//"):
        problems.append("unc-style")
    if any(part in ("", ".", "..") for part in raw.split("/")):
        problems.append("escapes the repository")
    if raw.startswith("-"):
        problems.append("begins with a dash")
    if _UNSAFE_PATH_CHARS.search(raw):
        problems.append("contains a character that is unsafe in a path, a log or a prompt")
    if "%" in raw and re.search(r"%2[fFeE]", raw):
        problems.append("url-encoded")
    if problems:
        raise ValueError(
            f"{field} is not a safe repository-relative path ({', '.join(problems)}): {value!r}"
        )
    return raw


def digest_of(file_path: str, start: int, end: int, probe_id: str, klass: str) -> str:
    seed = f"{file_path}|{start}-{end}|{probe_id}|{klass}"
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


def makes_an_unsupported_claim(text: str) -> bool:
    return bool(CLAIM_WORDS.search(text))


class LineRange(Model):
    start: int = Field(ge=1, le=200000)
    end: int = Field(ge=1, le=200000)

    @field_validator("end")
    @classmethod
    def _sane_span(cls, end: int, info) -> int:
        start = info.data.get("start", 1)
        if end < start:
            raise ValueError("line range ends before it starts")
        if end - start > MAX_LINE_SPAN:
            raise ValueError(f"line range spans more than {MAX_LINE_SPAN} lines")
        return end


class ProbePlan(Model):
    probe_id: str
    purpose: str = Field(max_length=240)
    expected_signal: str = Field(max_length=240)

    @field_validator("purpose", "expected_signal")
    @classmethod
    def _printable(cls, value: str, info) -> str:
        return printable(value, info.field_name)

    @field_validator("probe_id")
    @classmethod
    def _known_probe(cls, value: str) -> str:
        if value not in ALLOWED_PROBES:
            raise ValueError(
                f"probe {value!r} is not allowlisted; allowed: {', '.join(ALLOWED_PROBES)}"
            )
        return value


class FindingProposal(Model):
    """What Red claims. Absent by design: status, confirmation, and any test result."""

    summary: str = Field(min_length=20, max_length=320)
    vulnerability_class: str = Field(max_length=60)
    file_path: str = Field(max_length=240)
    line: LineRange
    data_flow: list[str] = Field(min_length=1, max_length=8)
    preconditions: str = Field(max_length=240)
    probe: ProbePlan
    confidence: float = Field(ge=0, le=1)
    limitations: str = Field(max_length=280)
    proposal_id: str = ""

    @field_validator("file_path")
    @classmethod
    def _path(cls, value: str) -> str:
        return safe_relative_path(value, "file_path")

    @field_validator("summary", "limitations", "preconditions", "vulnerability_class")
    @classmethod
    def _no_control_chars(cls, value: str, info) -> str:
        return printable(value, info.field_name)

    @field_validator("summary")
    @classmethod
    def _summary_claims_nothing(cls, value: str) -> str:
        if makes_an_unsupported_claim(value):
            raise ValueError("a finding summary may not assert that code is secure, safe or fixed")
        return value

    @field_validator("data_flow")
    @classmethod
    def _flow(cls, values: list[str]) -> list[str]:
        out = []
        for step in values:
            step = step.strip()
            if len(step) < 3:
                raise ValueError("data flow steps must be real descriptions")
            if len(step) > 240:
                raise ValueError("data flow step too long")
            printable(step, "data_flow step")
            out.append(step)
        return out

    @model_validator(mode="after")
    def _bind_identity(self) -> "FindingProposal":
        self.proposal_id = digest_of(
            self.file_path,
            self.line.start,
            self.line.end,
            self.probe.probe_id,
            self.vulnerability_class,
        )
        return self

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line.start}-{self.line.end}"

    @property
    def in_class(self) -> bool:
        return self.vulnerability_class == VULNERABILITY_CLASS


class TestRun(Model):
    """One recorded execution of one probe -- the only thing that can confirm anything.

    `proposal_id` is the digest of the hypothesis that was tested. A run without it is
    treated as unknown evidence, not as generic evidence.
    """

    __test__ = False  # the name matches the PRD's record; pytest must not collect it

    probe_id: str = Field(min_length=3, max_length=60)
    proposal_id: str = Field(default="", max_length=40)
    run_id: str = Field(default="", max_length=40)
    exit_code: int | None = None
    reproduced: bool | None = None
    timed_out: bool = False
    environment_id: str = Field(max_length=80)
    output_summary: str = Field(max_length=1200)
    elapsed_s: float = Field(ge=0, le=3600)

    @field_validator("output_summary")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value):
            raise ValueError("output summary contains control characters")
        return value

    @property
    def usable(self) -> bool:
        return self.reproduced is not None and not self.timed_out and self.exit_code is not None


def grounding_problems(proposal: FindingProposal, files: list[tuple[str, int]]) -> list[str]:
    """Is the cited location actually in the snapshot the model was shown?

    `files` is (path, line_count). An empty list means the caller has no snapshot to
    check against, which is reported as a problem rather than assumed to be fine.
    """
    if not files:
        return ["no snapshot was supplied, so the cited location could not be checked"]

    sizes = {path: lines for path, lines in files}
    if proposal.file_path not in sizes:
        return [f"cited file is not in the snapshot: {proposal.file_path}"]
    available = sizes[proposal.file_path]
    if proposal.line.end > available:
        return [f"cited lines {proposal.line.start}-{proposal.line.end} exceed a {available}-line file"]
    return []


def classify_finding(
    proposal: FindingProposal,
    runs: list[TestRun],
    files: list[tuple[str, int]] | None = None,
) -> FindingStatus:
    """Evidence decides, and contradictory or missing evidence never upgrades a claim."""
    if not proposal.in_class:
        return "unable_to_validate"

    if files is not None and grounding_problems(proposal, files):
        return "unable_to_validate"

    matching = [
        r
        for r in runs
        if r.probe_id == proposal.probe.probe_id and r.proposal_id == proposal.proposal_id
    ]
    if not matching:
        return "unable_to_validate"

    contradictory = [
        r for r in matching if r.reproduced is True and (r.timed_out or r.exit_code not in (None, 0))
    ]
    incomplete = [r for r in matching if not r.usable]
    if contradictory or incomplete:
        return "unable_to_validate"

    if any(r.reproduced is True for r in matching):
        return "confirmed"
    return "unconfirmed"


class PatchProposal(Model):
    """Blue's patch. Also absent by design: any field claiming the issue is fixed."""

    root_cause: str = Field(min_length=20, max_length=900)
    risks: str = Field(max_length=400)
    assumptions: str = Field(max_length=400)
    diff: str = Field(min_length=10, max_length=40000)
    changed_files: list[str] = Field(min_length=1, max_length=20)

    @field_validator("root_cause", "risks", "assumptions")
    @classmethod
    def _printable(cls, value: str, info) -> str:
        return printable(value, info.field_name)

    @field_validator("changed_files")
    @classmethod
    def _files(cls, values: list[str]) -> list[str]:
        return [safe_relative_path(v, "changed_files[]") for v in values]

    @field_validator("diff")
    @classmethod
    def _is_a_diff_without_control_chars(cls, value: str) -> str:
        if "diff --git" not in value and not (
            value.lstrip().startswith(("--- ", "@@")) and "+++ " in value
        ):
            raise ValueError("patch is not a reviewable unified diff")
        if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value):
            raise ValueError("diff contains control characters")
        return value

    @model_validator(mode="after")
    def _diff_stays_inside_the_declared_files(self) -> "PatchProposal":
        """Checked after both fields exist -- a field validator on `diff` cannot see
        `changed_files`, which is declared after it."""
        targets = re.findall(r"^(?:diff --git a/\S+|\+\+\+|---)[ \t]+(\S+)", self.diff, flags=re.MULTILINE)
        declared = set(self.changed_files)
        for target in targets:
            if target == "/dev/null":
                continue
            candidate = target[2:] if target[:2] in ("a/", "b/") else target
            normalised = safe_relative_path(candidate, "diff target")
            if normalised not in declared:
                raise ValueError(
                    f"diff touches {normalised!r}, which is not in changed_files ({', '.join(sorted(declared))})"
                )
        return self


class RegressionRun(Model):
    name: str = Field(min_length=2, max_length=80)
    passed: bool | None = None
    timed_out: bool = False

    @property
    def usable(self) -> bool:
        return self.passed is not None and not self.timed_out


def retest_verdict(
    proposal: FindingProposal,
    retest: TestRun | None,
    regressions: list[RegressionRun],
) -> tuple[RetestStatus, str]:
    """(status, reason). `fixed` needs the same probe, the same hypothesis, a clean exit,
    no reproduction, and recorded regression checks that pass. Nothing here can be
    satisfied by a claim."""
    if retest is None:
        return "inconclusive", "no retest was recorded"
    if retest.probe_id != proposal.probe.probe_id:
        return "inconclusive", "the retest ran a different probe than the finding asked for"
    if retest.proposal_id and retest.proposal_id != proposal.proposal_id:
        return "inconclusive", "the retest is bound to a different hypothesis than this finding"
    if not retest.proposal_id:
        return "inconclusive", "the retest did not record which hypothesis it tested"
    if not retest.usable:
        return "inconclusive", "the retest did not complete, so it proves nothing"
    if retest.exit_code != 0:
        return "inconclusive", f"the retest itself exited {retest.exit_code}, so its result is not trustworthy"
    if retest.reproduced:
        return "unresolved", "the original test still reproduces the issue"
    if not regressions:
        return "inconclusive", "no regression checks were recorded"
    if any(not r.usable for r in regressions):
        return "inconclusive", "one or more regression checks did not complete"
    if any(r.passed is False for r in regressions):
        return "unresolved", "the fix broke expected behaviour"
    return "fixed", "the original test no longer reproduces and all regression checks pass"


class Pointer(Model):
    """One line in the Spectator's list. Uncited pointers are dropped, not shown."""

    pointer_id: str = Field(min_length=3, max_length=40)
    text: str = Field(min_length=10, max_length=300)
    evidence_ids: list[str] = Field(min_length=1, max_length=6)

    @field_validator("text")
    @classmethod
    def _printable_text(cls, value: str) -> str:
        return printable(value, "pointer text")

    @field_validator("evidence_ids")
    @classmethod
    def _uniq(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(v.strip() for v in values if v.strip()))
        for value in cleaned:
            if _UNSAFE_PATH_CHARS.search(value):
                raise ValueError("evidence ids must be plain identifiers")
        return cleaned


def pointer_is_backed(pointer: Pointer, known_ids: set[str]) -> bool:
    return bool(pointer.evidence_ids) and set(pointer.evidence_ids) <= known_ids


class Approval(Model):
    """An approval is bound to a subject *and* to the exact bytes it covered."""

    subject_type: Literal["pointer", "patch"]
    subject_id: str = Field(min_length=3, max_length=60)
    subject_digest: str = Field(min_length=6, max_length=64)
    granted: bool = True
    decided_by: str = Field(max_length=40)
    note: str = Field(max_length=240)

    @field_validator("note", "decided_by")
    @classmethod
    def _printable(cls, value: str, info) -> str:
        return printable(value, info.field_name)

    @field_validator("decided_by")
    @classmethod
    def _who(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an approval needs a human on record")
        return value.strip()


def diff_digest(diff: str) -> str:
    return hashlib.sha256(diff.encode()).hexdigest()[:16]


def patch_is_approved(
    patch_id: str, patch_digest: str, approvals: list[Approval]
) -> bool:
    """True only if a human approved this id with this exact content."""
    return any(
        a.subject_type == "patch"
        and a.subject_id == patch_id
        and a.granted
        and a.subject_digest == patch_digest
        for a in approvals
    )


class CheckItemDraft(Model):
    """The shape the analyst model is asked to return."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    file_path: str = Field(max_length=240)
    line_start: int | None = Field(default=None, ge=1, le=200000)
    line_end: int | None = Field(default=None, ge=1, le=200000)
    indicator: str = Field(min_length=10, max_length=300)
    rule_id: str | None = Field(default=None, max_length=80)
    source: Literal["manager", "scanner"] = "manager"

    @field_validator("file_path")
    @classmethod
    def _path(cls, value: str) -> str:
        return safe_relative_path(value, "file_path")


class RepoCheckReply(Model):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    items: list[CheckItemDraft] = Field(default_factory=list, max_length=25)


class CheckItem(Model):
    """A Repo Check line item. `confirmed` is only reachable from a real scanner record."""

    file_path: str = Field(max_length=240)
    line: LineRange | None = None
    indicator: str = Field(min_length=10, max_length=300)
    rule_id: str | None = Field(default=None, max_length=80)
    source: Literal["scanner", "manager"] = "manager"

    @field_validator("file_path")
    @classmethod
    def _path(cls, value: str) -> str:
        return safe_relative_path(value, "file_path")

    @field_validator("indicator")
    @classmethod
    def _printable(cls, value: str) -> str:
        return printable(value, "indicator")

    @property
    def status(self) -> CheckStatus:
        if self.source == "scanner" and self.rule_id and self.line:
            return "confirmed"
        if self.line or self.rule_id:
            return "potential"
        return "inconclusive"

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line.start}" if self.line else self.file_path


def render_check_summary(items: list[CheckItem]) -> str:
    """The honest closing line of a Repo Check report."""
    counts = {"confirmed": 0, "potential": 0, "inconclusive": 0}
    for item in items:
        counts[item.status] += 1
    if not items:
        return (
            "Nothing detected by the checks that were run. "
            "These checks do not certify this repository."
        )
    return (
        f"{counts['confirmed']} confirmed by scanner rule, "
        f"{counts['potential']} potential, {counts['inconclusive']} inconclusive. "
        "Only a recorded test certifies anything; a clean scan certifies nothing."
    )
