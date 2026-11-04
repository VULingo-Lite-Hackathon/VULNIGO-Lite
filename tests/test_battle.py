from agents import fixtures
from agents.battle import decide, propose_defence, run_attack, run_battle
from agents.contract import Pointer
from agents.demo_run import CannedModel
from agents.inference import ModelUnavailable

FILES = fixtures.sample_files()
RUN_ID = f"run-{fixtures.proposal().proposal_id[:6]}"


def scripted(*, probes, replies=None, max_rounds=2):
    """A probe runner fed by a list of outcomes, plus the canned agents they belong to."""
    queue = list(probes)
    model = CannedModel(replies or {"red": [fixtures.proposal() for _ in range(max_rounds)],
                                   "blue": [fixtures.patch()], "manager": []})

    def probe_runner(proposal):
        if not queue:
            raise AssertionError("probe_runner called more times than scripted")
        return fixtures.run_for(proposal, **queue.pop(0))

    return probe_runner, model


def test_run_attack_confirms_only_when_the_bound_probe_reproduces():
    probe_runner, model = scripted(probes=[{}])
    attack = run_attack(asker=model, files=FILES, commit="c", probe_runner=probe_runner)
    assert attack.confirmed and attack.status == "confirmed"
    assert len(attack.evidence) == 1


def test_run_attack_refines_once_then_still_reports_the_truth():
    probe_runner, model = scripted(probes=[{"reproduced": False}, {"reproduced": True}])
    attack = run_attack(asker=model, files=FILES, commit="c", probe_runner=probe_runner)
    assert attack.status == "confirmed"
    assert model.calls == ["red", "red"]
    assert len(attack.evidence) == 2


def test_run_attack_stops_at_unconfirmed_and_says_so():
    probe_runner, model = scripted(probes=[{"reproduced": False}, {"reproduced": False}])
    attack = run_attack(asker=model, files=FILES, commit="c", probe_runner=probe_runner)
    assert attack.status == "unconfirmed"
    assert "no probe reproduced" in attack.reason


def test_a_probe_that_cannot_run_is_not_a_verdict():
    def broken(proposal):
        raise OSError("docker daemon unreachable")

    _runner, model = scripted(probes=[])
    attack = run_attack(asker=model, files=FILES, commit="c", probe_runner=broken)
    assert attack.status == "unable_to_validate"
    assert "could not run" in attack.reason


def test_decide_refuses_to_call_it_fixed_without_an_approval_on_the_exact_diff():
    probe_runner, model = scripted(probes=[{}])
    attack = run_attack(asker=model, files=FILES, commit="c", probe_runner=probe_runner)
    patch = propose_defence(model, attack)

    retest = fixtures.run_for(attack.proposal, reproduced=False)
    regressions = [fixtures.regression()]

    unapproved = decide(attack, patch, approvals=[], retest=retest, regressions=regressions)
    assert unapproved.applied is False and unapproved.verdict == "inconclusive"
    assert "approval" in unapproved.reason

    approval = fixtures.approval(patch.patch, subject_id=patch.patch_id)
    approved = decide(attack, patch, approvals=[approval], retest=retest, regressions=regressions)
    assert approved.applied is True and approved.verdict == "fixed"

    other = fixtures.patch(diff=fixtures.patch().diff.replace("200x200", "400x400"))
    stale = fixtures.approval(other, subject_id=patch.patch_id)
    mismatched = decide(attack, patch, approvals=[stale], retest=retest, regressions=regressions)
    assert mismatched.applied is False


def test_run_battle_walks_the_whole_loop_and_never_replaces_what_it_recorded():
    probe_runner, model = scripted(
        probes=[{}, {"reproduced": False, "output_summary": "marker absent"}],
        replies={"red": [fixtures.proposal()], "blue": [fixtures.patch()],
                 "manager": [
                     Pointer(pointer_id="ptr-attack", text="Red reproduced the injection inside the sandbox",
                             evidence_ids=[RUN_ID]),
                     Pointer(pointer_id="ptr-defense", text="Blue proposed a patch that passes the name as an argument",
                             evidence_ids=[RUN_ID]),
                     Pointer(pointer_id="ptr-retest", text="The original probe no longer reproduces; regressions pass",
                             evidence_ids=[RUN_ID]),
                 ]},
        max_rounds=1,
    )
    outcome = run_battle(
        asker=model,
        files=FILES,
        commit="c",
        probe_runner=probe_runner,
        regression_runner=lambda patch: [fixtures.regression()],
        approver=lambda patch: fixtures.approval(patch.patch, subject_id=patch.patch_id),
        max_rounds=1,
        spectate=True,
    )
    assert outcome.verdict == "fixed" and outcome.applied
    assert len(outcome.pointers) == 3 and outcome.dropped_pointers == []
    assert model.calls.count("manager") == 3


def test_run_battle_does_not_ask_for_a_patch_when_nothing_was_reproduced():
    probe_runner, model = scripted(probes=[{"reproduced": False}], max_rounds=1)
    outcome = run_battle(asker=model, files=FILES, commit="c", probe_runner=probe_runner, max_rounds=1)
    assert outcome.status == "unconfirmed"
    assert "blue" not in model.calls
    assert outcome.patch is None
    assert "never reproduced" in outcome.reason


def test_run_battle_reports_a_dead_defender_as_inconclusive_not_as_unresolved():
    probe_runner, model = scripted(
        probes=[{}], replies={"red": [fixtures.proposal()], "blue": [ModelUnavailable("429")], "manager": []}
    )
    outcome = run_battle(asker=model, files=FILES, commit="c", probe_runner=probe_runner, max_rounds=1)
    assert outcome.status == "confirmed"
    assert outcome.verdict == "inconclusive"
    assert "defender model was unavailable" in outcome.reason


def test_headline_always_names_the_status_and_the_reason():
    probe_runner, model = scripted(probes=[{"reproduced": False}], max_rounds=1)
    outcome = run_battle(asker=model, files=FILES, commit="c", probe_runner=probe_runner, max_rounds=1)
    assert outcome.headline().startswith("unconfirmed / inconclusive -- app.py:12-13")
