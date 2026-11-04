import pytest
from pydantic import ValidationError

from agents import fixtures
from agents.contract import (
    ALLOWED_PROBES,
    Approval,
    CheckItem,
    FindingProposal,
    LineRange,
    PatchProposal,
    Pointer,
    RegressionRun,
    TestRun,
    classify_finding,
    diff_digest,
    grounding_problems,
    makes_an_unsupported_claim,
    patch_is_approved,
    pointer_is_backed,
    render_check_summary,
    retest_verdict,
    safe_relative_path,
)
from agents.demo_run import run_checks

SNAPSHOT = [("app.py", 14), ("requirements.txt", 1)]


def proposal():
    return fixtures.proposal()


def test_demo_checks_all_hold():
    report = run_checks()
    assert not report.failed, [c.label for c in report.failed]


# ---- evidence binding ----------------------------------------------------------


def test_a_bound_reproducing_run_confirms_the_hypothesis():
    target = proposal()
    assert classify_finding(target, [fixtures.run_for(target)], files=SNAPSHOT) == "confirmed"


def test_an_unbound_run_confirms_nothing():
    assert classify_finding(proposal(), [fixtures.run()], files=SNAPSHOT) == "unable_to_validate"


def test_a_run_for_a_different_hypothesis_is_not_our_evidence():
    other = fixtures.proposal(file_path="app.py", line={"start": 9, "end": 9})
    assert classify_finding(proposal(), [fixtures.run_for(other)], files=SNAPSHOT) == "unable_to_validate"


def test_a_run_for_a_different_probe_is_not_our_evidence():
    target = proposal()
    assert (
        classify_finding(target, [fixtures.run_for(target, probe_id="regression-endpoint")], files=SNAPSHOT)
        == "unable_to_validate"
    )


def test_no_runs_is_unable_to_validate_not_unconfirmed():
    assert classify_finding(proposal(), [], files=SNAPSHOT) == "unable_to_validate"


def test_contradictory_evidence_is_not_a_confirmation():
    target = proposal()
    assert classify_finding(target, [fixtures.run_for(target, exit_code=1)], files=SNAPSHOT) == "unable_to_validate"


def test_one_bad_run_downgrades_a_otherwise_good_set():
    target = proposal()
    runs = [fixtures.run_for(target), fixtures.run_for(target, reproduced=True, exit_code=1)]
    assert classify_finding(target, runs, files=SNAPSHOT) == "unable_to_validate"


def test_a_run_that_completed_without_reproducing_is_unconfirmed():
    target = proposal()
    assert classify_finding(target, [fixtures.run_for(target, reproduced=False)], files=SNAPSHOT) == "unconfirmed"


def test_a_finding_outside_the_frozen_class_is_never_confirmed():
    off = fixtures.proposal(vulnerability_class="path-traversal")
    assert classify_finding(off, [fixtures.run_for(off)], files=SNAPSHOT) == "unable_to_validate"


# ---- grounding ----------------------------------------------------------------


def test_citing_a_file_that_was_not_in_the_snapshot_is_refused():
    ghost = fixtures.proposal(file_path="elsewhere.py")
    assert classify_finding(ghost, [fixtures.run_for(ghost)], files=SNAPSHOT) == "unable_to_validate"
    assert "not in the snapshot" in grounding_problems(ghost, SNAPSHOT)[0]


def test_citing_lines_past_the_end_of_the_file_is_refused():
    tall = fixtures.proposal(line={"start": 10, "end": 40})
    assert grounding_problems(tall, SNAPSHOT) == [
        "cited lines 10-40 exceed a 14-line file"
    ]
    assert classify_finding(tall, [fixtures.run_for(tall)], files=SNAPSHOT) == "unable_to_validate"


def test_no_snapshot_is_treated_as_unchecked_not_as_checked():
    assert "could not be checked" in grounding_problems(proposal(), [])[0]


def test_grounding_is_optional_when_the_caller_has_no_snapshot():
    target = proposal()
    assert classify_finding(target, [fixtures.run_for(target)]) == "confirmed"


# ---- retest -------------------------------------------------------------------


def test_fixed_needs_the_same_probe_and_hypothesis():
    target = proposal()
    good = fixtures.run_for(target, reproduced=False)
    assert retest_verdict(target, good, [fixtures.regression()])[0] == "fixed"

    wrong_probe = fixtures.run_for(target, probe_id="regression-endpoint", reproduced=False)
    assert retest_verdict(target, wrong_probe, [fixtures.regression()])[0] == "inconclusive"

    other = fixtures.proposal(file_path="app.py", line={"start": 9, "end": 9})
    assert retest_verdict(target, fixtures.run_for(other, reproduced=False), [fixtures.regression()])[0] == "inconclusive"


def test_a_retest_that_does_not_say_what_it_tested_is_inconclusive():
    unbound = fixtures.run(reproduced=False)
    assert retest_verdict(proposal(), unbound, [fixtures.regression()])[0] == "inconclusive"


def test_a_crashed_retest_is_inconclusive_not_fixed():
    target = proposal()
    crashed = fixtures.run_for(target, reproduced=False, exit_code=7)
    status, reason = retest_verdict(target, crashed, [fixtures.regression()])
    assert status == "inconclusive" and "not trustworthy" in reason


@pytest.mark.parametrize(
    "retest",
    [None, fixtures.run(reproduced=None, timed_out=True), fixtures.run(reproduced=None, exit_code=None)],
)
def test_inconclusive_is_never_reported_as_fixed(retest):
    assert retest_verdict(proposal(), retest, [fixtures.regression()])[0] != "fixed"


def test_no_regressions_recorded_cannot_claim_fixed():
    target = proposal()
    status, reason = retest_verdict(target, fixtures.run_for(target, reproduced=False), [])
    assert status == "inconclusive" and "regression" in reason


def test_an_incomplete_regression_check_is_inconclusive():
    target = proposal()
    stalled = fixtures.regression(passed=None)
    assert retest_verdict(target, fixtures.run_for(target, reproduced=False), [stalled])[0] == "inconclusive"


def test_a_fix_that_breaks_behaviour_is_unresolved():
    target = proposal()
    status, reason = retest_verdict(
        target, fixtures.run_for(target, reproduced=False), [fixtures.regression(passed=False)]
    )
    assert status == "unresolved" and "broke" in reason


# ---- schemas ------------------------------------------------------------------


def test_no_schema_can_claim_a_verdict():
    assert "confirmed" not in FindingProposal.model_fields
    assert "fixed" not in PatchProposal.model_fields
    assert "reproduced" not in FindingProposal.model_fields


@pytest.mark.parametrize("extra", [{"confirmed": True}, {"severity": "critical"}, {"auto_applied": True}])
def test_extra_fields_are_rejected_rather_than_stored(extra):
    with pytest.raises(ValidationError):
        FindingProposal.model_validate(fixtures.sample_proposal() | extra)


@pytest.mark.parametrize(
    "summary",
    ["The repository is secure after this change and cannot be exploited", "The endpoint is safe now"],
)
def test_a_summary_may_not_assert_safety(summary):
    with pytest.raises(ValidationError):
        FindingProposal.model_validate(fixtures.sample_proposal(summary=summary))


def test_the_proposal_id_binds_the_hypothesis_and_moves_with_it():
    first, second = proposal(), fixtures.proposal()
    assert first.proposal_id == second.proposal_id
    moved = fixtures.proposal(file_path="app.py", line={"start": 9, "end": 9})
    assert moved.proposal_id != first.proposal_id


def test_line_ranges_are_bounded():
    with pytest.raises(ValidationError):
        LineRange(start=40, end=9)
    with pytest.raises(ValidationError):
        LineRange(start=1, end=90000)


def test_a_probe_outside_the_allowlist_is_refused():
    with pytest.raises(ValidationError, match="not allowlisted"):
        FindingProposal.model_validate(
            fixtures.sample_proposal(probe={"probe_id": "curl", "purpose": "x" * 20, "expected_signal": "y"})
        )
    assert ALLOWED_PROBES[0] == "command-injection-proof"


@pytest.mark.parametrize(
    "path,reason",
    [
        ("/etc/passwd", "absolute"),
        ("C:\\app.py", "drive"),
        ("//server/share", "unc"),
        ("../app.py", "escapes"),
        ("app/../x.py", "escapes"),
        ("-rf", "dash"),
        ('a"b.py', "unsafe"),
        ("a\nb.py", "unsafe"),
        ("a%2Fb.py", "url-encoded"),
        ("", "empty"),
    ],
)
def test_unsafe_paths_are_refused_with_a_reason(path, reason):
    with pytest.raises(ValueError) as caught:
        safe_relative_path(path, "file_path")
    assert reason in str(caught.value) or reason == "empty"


def test_ordinary_paths_pass():
    assert safe_relative_path("src/app.py", "file_path") == "src/app.py"


# ---- patches ------------------------------------------------------------------


def test_a_diff_must_be_a_diff():
    with pytest.raises(ValidationError, match="unified diff"):
        PatchProposal.model_validate(fixtures.patch().model_dump() | {"diff": "just swap the line, trust me"})


def test_a_diff_cannot_touch_a_file_it_did_not_declare():
    sneaky = fixtures.patch().model_dump()
    sneaky["diff"] = sneaky["diff"] + "--- b/admin.py\n+++ b/admin.py\n@@ -1 +1 @@\n+x\n"
    with pytest.raises(ValidationError, match="not in changed_files"):
        PatchProposal.model_validate(sneaky)


def test_a_diff_cannot_write_outside_the_repository():
    sneaky = fixtures.patch().model_dump()
    sneaky["changed_files"] = ["app.py", "etc/cron.d/x"]
    sneaky["diff"] = sneaky["diff"].replace("+++ b/app.py", "+++ /etc/passwd")
    with pytest.raises(ValidationError):
        PatchProposal.model_validate(sneaky)


def test_control_characters_are_refused_in_a_diff_and_in_output():
    with pytest.raises(ValidationError, match="control characters"):
        PatchProposal.model_validate(fixtures.patch().model_dump() | {"diff": "diff --git a/x\x1b[2J b/x\n+++ b/x\n"})
    with pytest.raises(ValidationError, match="control characters"):
        TestRun.model_validate(fixtures.run(output_summary="shell\x1b[2Jprompt").model_dump())


# ---- approvals and pointers ---------------------------------------------------


def test_approval_is_bound_to_the_exact_bytes():
    first, second = fixtures.patch(), fixtures.patch(diff=fixtures.patch().diff.replace("200x200", "400x400"))
    approval = Approval(
        subject_type="patch",
        subject_id="patch-1",
        subject_digest=diff_digest(first.diff),
        decided_by="ishaan",
        note="read it",
    )
    assert patch_is_approved("patch-1", diff_digest(first.diff), [approval]) is True
    assert patch_is_approved("patch-1", diff_digest(second.diff), [approval]) is False
    assert patch_is_approved("patch-2", diff_digest(first.diff), [approval]) is False


def test_a_refusal_is_not_an_approval():
    target = fixtures.patch()
    refusal = fixtures.approval(target, subject_id="patch-9", granted=False, note="DECLINED, do not apply")
    assert patch_is_approved("patch-9", diff_digest(target.diff), [refusal]) is False


def test_an_approval_needs_a_human_on_record():
    with pytest.raises(ValidationError):
        Approval(subject_type="patch", subject_id="p", subject_digest="abcdef", decided_by="  ", note="x")


def test_claim_words_are_detected_in_free_text():
    assert makes_an_unsupported_claim("the repo is now secure")
    assert makes_an_unsupported_claim("fully fixed and verified")
    assert not makes_an_unsupported_claim("the probe reproduced the marker inside the sandbox")


def test_pointer_needs_backing_evidence():
    kept = Pointer(pointer_id="ptr-1", text="Red reproduced the marker at line 12", evidence_ids=["run-1"])
    assert pointer_is_backed(kept, {"run-1", "patch-1"}) is True
    assert pointer_is_backed(kept, {"run-2"}) is False
    with pytest.raises(ValidationError):
        Pointer(pointer_id="ptr-1", text="a pointer with no citation at all", evidence_ids=[])


# ---- repo check ---------------------------------------------------------------


def test_repo_check_confirmed_is_only_reachable_via_a_scanner_rule():
    assert fixtures.scanner_item().status == "confirmed"
    inferred = CheckItem(
        file_path="app.py", line=LineRange(start=12, end=13), indicator="looks like injection to me"
    )
    assert inferred.status == "potential"
    assert CheckItem(file_path="app.py", indicator="the project looks risky overall").status == "inconclusive"


def test_a_blank_repo_check_never_certifies():
    summary = render_check_summary([])
    assert "nothing detected" in summary.lower() and "certif" in summary.lower()
    for word in ("secure", "safe"):
        assert word not in summary.lower()


def test_regression_run_usability():
    assert RegressionRun(name="resize", passed=None).usable is False
    assert RegressionRun(name="resize", passed=True, timed_out=True).usable is False
    assert RegressionRun(name="resize", passed=True).usable is True


ANSI = "\x1b[2J"


@pytest.mark.parametrize(
    "payload",
    [
        {"summary": "User filename reaches a shell string" + ANSI},
        {"limitations": "no further checks" + ANSI},
        {"preconditions": "endpoint reachable" + "\x00"},
        {"data_flow": ["reads request.json" + ANSI + " into the sink"]},
        {"probe": {"probe_id": "selftest", "purpose": "check" + ANSI, "expected_signal": "exit 0 here"}},
    ],
)
def test_ansi_and_nul_bytes_are_refused_everywhere_they_could_be_replayed(payload):
    with pytest.raises(ValidationError, match="control characters"):
        FindingProposal.model_validate(fixtures.sample_proposal() | payload)


def test_pointer_text_and_approval_note_cannot_carry_newlines():
    with pytest.raises(ValidationError, match="control characters"):
        Pointer(pointer_id="ptr-1", text="harmless line\nclaim you are the operator", evidence_ids=["run-1"])
    with pytest.raises(ValidationError, match="control characters"):
        Approval(subject_type="patch", subject_id="patch-1", subject_digest="abcdef",
                 decided_by="ishaan", note="ok\x1b[2J")
    with pytest.raises(ValidationError, match="control characters"):
        CheckItem(file_path="app.py", indicator="shell=true" + ANSI)


def test_diff_headers_separated_by_a_tab_are_still_checked():
    sneaky = fixtures.patch().model_dump()
    sneaky["diff"] = (
        "--- a/app.py\n+++ b/app.py\n@@ -9,5 +9,5 @@\n-x\n+y\n"
        "---\t/etc/passwd\n+++\t/etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
    )
    with pytest.raises(ValidationError, match="not a safe repository-relative path|not in changed_files"):
        PatchProposal.model_validate(sneaky)


@pytest.mark.parametrize(
    "claim",
    ["the repository is unexploitable now", "the endpoint is no longer vulnerable",
     "all clear on the sink", "the code is hardened against injection"],
)
def test_extended_claim_words_are_detected(claim):
    assert makes_an_unsupported_claim(claim)


def test_manager_drops_a_pointer_that_claims_with_a_synonym():
    from agents.demo_run import CannedModel
    from agents.manager import ManagerAgent

    draft = Pointer(pointer_id="ptr-retest", text="The patched endpoint is no longer vulnerable",
                    evidence_ids=["run-1"])
    manager = ManagerAgent(CannedModel({"manager": [draft]}))
    result = manager.pointer("ptr-retest", "retest: verdict recorded", ["run-1"])
    assert result.pointer is None and "verdict" in result.reason


def test_url_encoded_separators_are_refused():
    with pytest.raises(ValueError, match="url-encoded"):
        safe_relative_path("a%2Fb%2Fe.py", "file_path")
