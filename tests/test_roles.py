import pytest

from agents import fixtures
from agents.backup import BackupAlreadySummoned, BackupRegistry, BattleState
from agents.blue import BlueAgent
from agents.contract import Pointer
from agents.demo_run import CannedModel
from agents.inference import BudgetExhausted, ModelUnavailable, UnvalidatedOutput
from agents.manager import ManagerAgent
from agents.red import RedAgent

FILES = fixtures.sample_files()


def test_red_returns_a_proposal_with_a_snapshot_and_no_status_of_its_own():
    result = RedAgent(CannedModel({"red": [fixtures.proposal()]})).propose(FILES, commit="abc123")
    assert result.in_scope is True
    assert ("app.py", 15) in result.snapshot
    assert result.problems() == []
    assert result.usage.total > 0


def test_red_reports_truncation_and_out_of_class_as_problems():
    huge = [fixtures.proposal(vulnerability_class="path-traversal")]
    result = RedAgent(CannedModel({"red": huge})).propose(FILES, commit="abc")
    assert not result.in_scope
    assert any("frozen class" in p for p in result.problems())


def test_red_can_be_asked_to_refine_and_keeps_both_rounds():
    model = CannedModel({"red": [fixtures.proposal(), fixtures.proposal(confidence=0.2)]})
    red = RedAgent(model)
    red.propose(FILES, commit="abc")
    red.refine(FILES, commit="abc", feedback="exit 1, marker absent")
    assert len(red.history) == 2
    assert model.calls == ["red", "red"]


def test_refine_feedback_is_the_recorded_result_not_an_opinion():
    model = CannedModel({"red": [fixtures.proposal()]})
    RedAgent(model).refine(FILES, commit="abc", feedback="probe exited 1, reproduced=False")
    assert "probe exited 1, reproduced=False" in model.seen_tasks[0]
    assert "not supported by the recorded evidence" in model.seen_tasks[0]


def test_a_seeded_agent_shares_the_seed_with_the_model():
    model = CannedModel({"red": [fixtures.proposal()]})
    agent = RedAgent(model)
    agent.seed("the player is stuck on round 2")
    agent.propose(FILES, commit="abc")
    assert model.seen_tasks[0].startswith("the player is stuck on round 2")


def test_blue_ids_patches_by_content_so_two_diffs_never_share_an_id():
    first = BlueAgent(CannedModel({"blue": [fixtures.patch()]})).explain(
        fixtures.proposal(), "confirmed", "marker present"
    )
    alternate = fixtures.patch(diff=fixtures.patch().diff.replace("200x200", "400x400"))
    second = BlueAgent(CannedModel({"blue": [alternate]})).explain(
        fixtures.proposal(), "confirmed", "marker present"
    )
    assert first.patch_id != second.patch_id
    assert first.digest != second.digest
    assert first.patch_id.startswith("patch-")


def test_blue_labels_a_patch_that_answers_an_unconfirmed_finding():
    outcome = BlueAgent(CannedModel({"blue": [fixtures.patch()]})).explain(
        fixtures.proposal(), "unconfirmed", "nothing reproduced"
    )
    assert outcome.addresses_unconfirmed_finding is True
    assert "never reproduced" in outcome.describe()


def test_blue_only_ever_sees_the_finding_and_its_evidence():
    model = CannedModel({"blue": [fixtures.patch()]})
    BlueAgent(model).explain(fixtures.proposal(), "confirmed", "marker present in the sandbox")
    task = model.seen_tasks[0]
    assert "marker present in the sandbox" in task
    assert "<untrusted-source" not in task, "Blue must not be handed the whole snapshot"


def test_manager_keeps_a_pointer_that_cites_real_evidence():
    manager = ManagerAgent(
        CannedModel({"manager": [Pointer(pointer_id="ptr-attack", text="Red reproduced the marker at line 12",
                                        evidence_ids=["run-1"])]})
    )
    result = manager.pointer("ptr-attack", "attack: probe reproduced the marker", ["run-1"])
    assert result.pointer is not None
    assert manager.dropped_pointers == []


@pytest.mark.parametrize(
    "draft,reason",
    [
        (Pointer(pointer_id="ptr-other", text="Red reproduced the marker at line 12", evidence_ids=["run-1"]),
         "model changed the pointer id"),
        (Pointer(pointer_id="ptr-attack", text="Red reproduced the marker at line 12", evidence_ids=["run-9"]),
         "cited evidence we do not hold"),
        (Pointer(pointer_id="ptr-attack", text="Blue fixed it; the repository is now secure",
                 evidence_ids=["run-1"]), "claimed a verdict no test recorded"),
    ],
)
def test_manager_drops_pointers_for_a_recorded_reason(draft, reason):
    manager = ManagerAgent(CannedModel({"manager": [draft]}))
    result = manager.pointer("ptr-attack", "attack: something happened", ["run-1"])
    assert result.pointer is None and result.reason == reason
    assert manager.dropped_pointers == [("ptr-attack", reason)]


@pytest.mark.parametrize("failure", [ModelUnavailable("down"), UnvalidatedOutput("bad", 3, "x"),
                                     BudgetExhausted("token budget exhausted")])
def test_a_failed_model_drops_the_pointer_instead_of_crashing_the_battle(failure):
    manager = ManagerAgent(CannedModel({"manager": [failure]}))
    result = manager.pointer("ptr-attack", "attack: something", ["run-1"])
    assert result.pointer is None and "model failed" in result.reason


def test_repo_check_strips_a_fabricated_scanner_identity():
    draft = fixtures.repo_draft(rule_id="python.fabricated.rule", source="scanner")
    outcome = ManagerAgent(CannedModel({"manager": [fixtures.repo_reply(draft)]})).repo_check(
        FILES, scanner_items=[], commit="abc"
    )
    assert len(outcome.items) == 1
    item = outcome.items[0]
    assert item.source == "manager" and item.rule_id is None
    assert item.status == "potential"
    assert not outcome.degraded


def test_repo_check_keeps_scanner_hits_and_dedupes_the_model_paraphrase():
    scanner = fixtures.scanner_item()
    echo = fixtures.repo_draft(file_path="app.py", line_start=12, indicator="subprocess with shell=true on request input")
    outcome = ManagerAgent(CannedModel({"manager": [fixtures.repo_reply(echo)]})).repo_check(
        FILES, scanner_items=[scanner], commit="abc"
    )
    assert len(outcome.items) == 1
    assert outcome.items[0].status == "confirmed"


def test_repo_check_degrades_loudly_when_the_analyst_is_unavailable():
    scanner = fixtures.scanner_item()
    outcome = ManagerAgent(CannedModel({"manager": [ModelUnavailable("429 too many requests")]})).repo_check(
        FILES, scanner_items=[scanner], commit="abc"
    )
    assert outcome.degraded is True
    assert outcome.items == [scanner]
    assert "PARTIAL RUN" in outcome.summary


def test_backup_seeds_the_same_agent_and_refuses_a_second_summon():
    registry = BackupRegistry()
    state = BattleState(
        side="blue",
        round_no=1,
        finding=fixtures.proposal(),
        context="assembled snapshot",
        transcript=["player cannot identify the sink"],
        evidence="marker present, exit 0",
    )
    spy = CannedModel({"blue": [fixtures.patch()]})
    agent = registry.summon("blue", spy, state)
    assert isinstance(agent, BlueAgent) and registry.is_active("blue")
    agent.explain(state.finding, "confirmed", "marker present")
    assert "You are joining as backup for the blue side" in spy.seen_tasks[0]
    assert "app.py:12-13" in spy.seen_tasks[0]

    with pytest.raises(BackupAlreadySummoned):
        registry.summon("blue", CannedModel({}), state)

    registry.summon("red", CannedModel({}), BattleState(side="red", round_no=2))
    assert registry.active_sides() == ["blue", "red"]
    assert "round 2" in registry.summary()


def test_backup_rejects_a_side_no_user_can_play():
    with pytest.raises(ValueError, match="not a side"):
        BackupRegistry().summon("manager", CannedModel({}), BattleState(side="red"))
