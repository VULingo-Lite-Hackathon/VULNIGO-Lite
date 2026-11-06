"""Battle controller: the deterministic state machine that drives every run.

Routine transitions are plain code. Models are consulted only for judgment (which candidate,
how to explain, what patch) and their output is validated before anything happens.
"""
import asyncio
import secrets
import time
from pathlib import Path

from . import agents, config, intake, patcher, report, sandbox, scanner, store
from .bus import bus
from .state import TERMINAL, S, check

MAX_ACTIVE = 4
MAX_REVISIONS = 2


class Run:
    def __init__(self, run_id: str, kind: str, repo_url: str | None, mode: str, side: str | None):
        self.id, self.kind, self.repo_url, self.mode, self.side = run_id, kind, repo_url, mode, side
        self.state = S.CREATED
        self.paths: dict = {}
        self.budget = agents.Budget()
        self.notes: dict[str, list[str]] = {"red": [], "blue": []}
        self.backup: set[str] = set()
        self.finding: dict | None = None
        self.candidate: dict | None = None
        self.patch_id: str | None = None
        self.round = "setup"
        self.waiting: str | None = None  # what the run is waiting on, if anything
        self._approval: asyncio.Future | None = None
        self._human: asyncio.Future | None = None
        self.task: asyncio.Task | None = None

    @property
    def is_demo(self) -> bool:
        return self.repo_url is None


RUNS: dict[str, Run] = {}


# ---------------------------------------------------------------- events
def emit(run: Run, agent: str, type_: str, message: str, ok: bool | None = None,
         finding_id: str | None = None, data: dict | None = None) -> None:
    row = store.insert("events", {"run_id": run.id, "ts": time.time(), "agent": agent, "type": type_,
                                  "message": message, "finding_id": finding_id,
                                  "ok": None if ok is None else int(ok), "data": data or {}})
    bus.publish(run.id, {**row, "state": run.state.value, "waiting": run.waiting, "round": run.round})


def agent_status(run: Run, agent: str, status: str, detail: str = "") -> None:
    """status in running | waiting | failed | completed | idle"""
    emit(run, agent, "agent_status", detail or status, data={"status": status})


def transition(run: Run, nxt: S, why: str = "") -> None:
    check(run.state, nxt)
    prev = run.state
    run.state = nxt
    store.update("runs", "id", run.id, status=nxt.value, updated_at=time.time())
    emit(run, "manager", "state", f"{prev.value} -> {nxt.value}" + (f": {why}" if why else ""),
         data={"from": prev.value, "to": nxt.value})


def pointer(run: Run, text: str, evidence: str | None) -> None:
    pid = store.new_id("pt")
    store.insert("pointers", {"id": pid, "run_id": run.id, "text": text, "evidence_ref": evidence,
                              "decision": "pending", "ts": time.time()})
    emit(run, "manager", "pointer", text, data={"pointer_id": pid, "evidence": evidence})


def label_agent(res: agents.AgentResult) -> str:
    return f"live model {res.model}" if res.live else f"DETERMINISTIC FALLBACK ({res.note})"


# ---------------------------------------------------------------- human interaction
async def wait_human(run: Run, what: str, prompt: str) -> dict | None:
    """Pause for a participating human. They can act or press 'let the agent continue'."""
    run.waiting = what
    run._human = asyncio.get_running_loop().create_future()
    emit(run, "manager", "human_turn", prompt, data={"what": what})
    try:
        return await asyncio.wait_for(run._human, config.APPROVAL_TIMEOUT)
    except asyncio.TimeoutError:
        emit(run, "manager", "info", "No response from participant; the agent continues.")
        return None
    finally:
        run.waiting, run._human = None, None


def submit_human(run: Run, payload: dict) -> None:
    if not run._human or run._human.done():
        raise ValueError("this battle is not waiting for a participant action")
    run._human.set_result(payload)


def submit_approval(run: Run, patch_id: str, decision: str, note: str) -> None:
    if run.state != S.AWAITING_APPROVAL or not run._approval or run._approval.done():
        raise ValueError("no patch is awaiting approval")
    if patch_id != run.patch_id:
        raise ValueError("approval refers to a different patch")
    if decision not in ("approved", "rejected", "changes_requested"):
        raise ValueError("decision must be approved, rejected or changes_requested")
    store.insert("approvals", {"id": store.new_id("ap"), "run_id": run.id, "patch_id": patch_id,
                               "decision": decision, "note": note[:500], "ts": time.time()})
    store.update("patches", "id", patch_id, approval_status=decision)
    emit(run, "human", "approval", f"Patch {patch_id}: {decision}" + (f" - {note}" if note else ""),
         ok=decision == "approved", data={"patch_id": patch_id, "decision": decision})
    run._approval.set_result((decision, note))


async def add_message(run: Run, text: str) -> None:
    side = run.side if run.mode == "participate" else None
    store.insert("messages", {"run_id": run.id, "sender": "human", "side": side or "spectator",
                              "text": text[:1000], "ts": time.time()})
    emit(run, "human", "chat", text[:1000], data={"side": side})
    if not side:
        return
    run.notes[side].append(text[:500])
    res = await agents.team_reply(side, text, run.finding, run.budget)
    emit(run, side, "chat", res.data["advice"], data={"live": res.live, "label": label_agent(res)})


async def request_backup(run: Run) -> None:
    if run.mode != "participate" or not run.side:
        raise ValueError("Need Backup is only available to an active participant")
    if run.state in TERMINAL:
        raise ValueError("battle is over")
    side = run.side
    first = side not in run.backup
    run.backup.add(side)
    store.insert("messages", {"run_id": run.id, "sender": "human", "side": side, "text": "[Need Backup]", "ts": time.time()})
    if first:
        emit(run, "backup", "backup", f"Backup agent joined the {side.upper()} team for the rest of the battle.",
             data={"side": side})
    agent_status(run, "backup", "running", "reviewing the situation")
    await _backup_say(run)


async def _backup_say(run: Run) -> None:
    side = run.side
    file_text = ""
    if run.finding:
        try:
            file_text = patcher.read(run.paths["work"], run.finding["file"])
        except (OSError, patcher.PatchError, KeyError):
            pass
    chat = store.list_for("messages", run.id)
    res = await agents.backup_advice(side, run.round, run.finding, file_text, chat, run.budget)
    emit(run, "backup", "backup", res.data["advice"],
         data={"side": side, "next_step": res.data.get("next_step"), "live": res.live, "label": label_agent(res)})
    agent_status(run, "backup", "completed", "advice given")


# ---------------------------------------------------------------- lifecycle
def create(kind: str, repo_url: str | None, mode: str, side: str | None) -> Run:
    active = sum(1 for r in RUNS.values() if r.state not in TERMINAL)
    if active >= MAX_ACTIVE:
        raise RuntimeError("Too many battles running right now; try again in a minute.")
    if repo_url is not None:
        repo_url = intake.validate_github_url(repo_url)  # reject early: no battle is created
    run_id = store.new_id("battle" if kind == "battle" else "check")
    run = Run(run_id, kind, repo_url, mode, side)
    store.insert("runs", {"id": run_id, "kind": kind, "repo_url": repo_url or "demo",
                          "repo_label": repo_url or "Prepared demo repository", "commit_hash": None, "mode": mode,
                          "side": side, "status": S.CREATED.value, "created_at": time.time(),
                          "updated_at": time.time(), "meta": {}})
    RUNS[run_id] = run
    run.task = asyncio.create_task(_guard(run))
    return run


async def _guard(run: Run) -> None:
    try:
        if run.kind == "battle":
            await _battle(run)
        else:
            await _repo_check(run)
    except Exception as e:  # never leave a run hanging or report something we didn't verify
        emit(run, "manager", "error", f"Internal error: {type(e).__name__}: {e}", ok=False)
        for nxt in (S.FAILED, S.ATTACK_INCONCLUSIVE, S.DEFENSE_INCONCLUSIVE, S.INCONCLUSIVE, S.PATCH_FAILED,
                    S.NO_CONFIRMED_FINDING, S.CHECK_INCONCLUSIVE):
            try:
                transition(run, nxt, "stopped after an internal error")
                break
            except Exception:
                continue
        if run.kind == "battle":
            report.build_battle_report(run.id)
    finally:
        intake.cleanup(run.id)
        emit(run, "manager", "done", "Run finished; sandbox data cleaned up.", data={"final": run.state.value})


async def _intake(run: Run) -> bool:
    transition(run, S.REPOSITORY_VALIDATING)
    agent_status(run, "manager", "running", "fetching repository")
    try:
        info = await intake.prepare(run.id, run.repo_url)
    except intake.IntakeError as e:
        emit(run, "manager", "error", str(e), ok=False)
        transition(run, S.FAILED, "repository intake failed")
        agent_status(run, "manager", "failed", str(e))
        return False
    run.paths = {"source": info["source"], "work": info["work"]}
    run.meta = info["meta"]
    store.update("runs", "id", run.id, commit_hash=info["commit_hash"], repo_label=info["label"], meta=info["meta"])
    emit(run, "manager", "info", f"Snapshot of {info['label']} at {info['commit_hash'][:24]} "
         f"({info['meta']['files']} files, {info['meta']['python_files']} Python).", data=info["meta"])
    return True


async def _battle(run: Run) -> None:
    if not await _intake(run):
        report.build_battle_report(run.id)
        return

    # ---- sandbox + containment probe (the visible containment moment)
    agent_status(run, "manager", "running", "starting sandbox")
    probe = await sandbox.run(run.id, "probe", run.paths["source"], is_demo=run.is_demo, label="containment probe")
    checks = ((probe["data"] or {}).get("result") or {}).get("checks", [])
    emit(run, "sandbox", "test", f"Containment probe: {probe['outcome'].upper()} "
         f"({sum(c['blocked'] for c in checks)}/{len(checks)} escape attempts blocked)" if checks
         else f"Containment probe: {probe['outcome'].upper()} - {probe['output'][:160]}",
         ok=probe["outcome"] == "pass", data={"test_id": probe["id"], "checks": checks,
                                               "policy": sandbox.describe_policy(), "sandboxed": bool(probe["sandboxed"])})
    transition(run, S.SANDBOX_READY)

    # ---- Round 1: attack
    run.round = "attack"
    transition(run, S.ATTACKING)
    agent_status(run, "red", "running", "scanning for command injection and path traversal")
    candidates = scanner.scan_battle_candidates(Path(run.paths["source"]))
    n_ci = sum(c["category"] == "command-injection" for c in candidates)
    emit(run, "red", "info", f"Deterministic scanner: {n_ci} command-injection (CWE-78) and "
         f"{len(candidates) - n_ci} path-traversal (CWE-22) candidate(s).",
         data={"candidates": [{"i": i, "file": c["file"], "line": c["line_start"], "function": c["function"],
                               "category": c["category"], "flow": c["data_flow"]} for i, c in enumerate(candidates)]})
    if not candidates:
        py = (getattr(run, "meta", None) or {}).get("python_files", 0)
        why = ("the repository has no Python files; Lite battles test Python code only (CWE-78 command injection, "
               "CWE-22 path traversal) - try Repo Check for a static scan of other languages" if not py
               else "the scanner found no command-injection or path-traversal candidates")
        transition(run, S.FINDINGS_REVIEW, "no candidates")
        transition(run, S.NO_CONFIRMED_FINDING, why)
        agent_status(run, "red", "completed", "nothing found")
        return await _finish(run)

    custom_payload = None
    forced_idx = None
    if run.mode == "participate" and run.side == "red":
        if "red" in run.backup:
            await _backup_say(run)
        act = await wait_human(run, "red_attack",
                               "Your move, Red: pick a candidate, add a hypothesis, optionally write a payload "
                               "(command injection: make it write to /tmp/vulnigo_proof; path traversal: make it "
                               "read ../../vulnigo_secret.txt), or let the Red Agent proceed.")
        if act:
            if act.get("hypothesis"):
                run.notes["red"].append(act["hypothesis"])
            if isinstance(act.get("candidate_index"), int) and 0 <= act["candidate_index"] < len(candidates):
                forced_idx = act["candidate_index"]
            custom_payload = (act.get("payload") or "")[:300] or None

    if forced_idx is not None:
        # The human picked the target: the agent writes the hypothesis for that candidate, not its own favourite.
        res = await agents.red_analyse([candidates[forced_idx]], run.budget, run.notes["red"])
        res.data["candidate_index"] = forced_idx
    else:
        res = await agents.red_analyse(candidates, run.budget, run.notes["red"])
    idx = res.data["candidate_index"]
    cand = candidates[idx]
    run.candidate = cand
    hypothesis = res.data["finding_summary"]
    emit(run, "red", "claim", f"Hypothesis: {hypothesis}", data={**res.data, "label": label_agent(res),
                                                                    "file": cand["file"], "line": cand["line_start"]})
    if not cand["top_level"]:
        emit(run, "red", "info", "Candidate is not a top-level function; the bounded proof harness cannot call it directly.")

    agent_status(run, "red", "running", "running bounded proof test in sandbox")
    spec = {"file": cand["file"], "function": cand["function"], "param": cand["param"], "params": cand["params"],
            "category": cand["category"], "token": "VG" + secrets.token_hex(6)}
    proof = await sandbox.run(run.id, "proof", run.paths["source"], spec, is_demo=run.is_demo, label="attack proof")
    _emit_test(run, "red", proof)
    human_proof = None
    if custom_payload:
        human_proof = await sandbox.run(run.id, "proof", run.paths["source"], {**spec, "custom_payload": custom_payload},
                                        is_demo=run.is_demo, label="attack proof (human payload)")
        _emit_test(run, "human", human_proof)

    outcomes = [proof["outcome"]] + ([human_proof["outcome"]] if human_proof else [])
    usable_outcomes = {outcome for outcome in outcomes if outcome in {"pass", "fail"}}
    if not all(outcome in {"pass", "fail"} for outcome in outcomes) or len(usable_outcomes) > 1:
        status = "inconclusive"
    elif "pass" in usable_outcomes:
        status = "confirmed"
    elif "fail" in usable_outcomes:
        status = "unconfirmed"
    else:
        status = "inconclusive"
    evidence_test = next((t for t in (proof, human_proof) if t and t["outcome"] == "pass"), proof)
    fid = store.new_id("fd")
    store.insert("findings", {"id": fid, "run_id": run.id, "category": cand["category"], "file": cand["file"],
                              "line_start": cand["line_start"], "line_end": cand["line_end"],
                              "function": cand["function"], "param": cand["param"], "hypothesis": hypothesis,
                              "status": status, "test_ref": evidence_test["id"],
                              "evidence": (evidence_test["data"] or {}).get("result"),
                              "source": "red-agent" + ("+human" if custom_payload or forced_idx is not None else ""),
                              "data": {**cand, "red": res.data}})
    run.finding = store.get("findings", fid)
    agent_status(run, "red", "completed" if status == "confirmed" else "failed", status)

    if status == "inconclusive":
        transition(run, S.ATTACK_INCONCLUSIVE, "proof test could not run")
        return await _finish(run)
    transition(run, S.FINDINGS_REVIEW)
    emit(run, "manager", "finding", f"Finding {fid} is {report.STATUS_WORDS[status].upper()} "
         f"({cand['file']}:{cand['line_start']}, evidence {evidence_test['id']}).",
         ok=status == "confirmed", finding_id=fid, data={"status": status})
    pointer(run, f"Red's claim about {cand['function']}() at {cand['file']}:{cand['line_start']} is "
            f"{report.STATUS_WORDS[status]} by sandbox test {evidence_test['id']}.", evidence_test["id"])
    if status != "confirmed":
        transition(run, S.NO_CONFIRMED_FINDING, "the bounded test did not reproduce the hypothesis")
        return await _finish(run)

    # ---- Round 2: defense
    run.round = "defense"
    transition(run, S.DEFENDING)
    revisions = 0
    while True:
        patch, res_label = await _defend(run, revisions)
        if not patch:
            transition(run, S.DEFENSE_INCONCLUSIVE, "no valid patch")
            return await _finish(run)
        transition(run, S.AWAITING_APPROVAL)
        agent_status(run, "manager", "waiting", "waiting for human approval of the patch")
        run.waiting = "approval"
        run._approval = asyncio.get_running_loop().create_future()
        emit(run, "manager", "approval_request", f"Patch {run.patch_id} is ready for review. Nothing is applied "
             "until you approve it.", data={"patch_id": run.patch_id, "diff": patch["diff"]})
        try:
            decision, note = await asyncio.wait_for(run._approval, config.APPROVAL_TIMEOUT)
        except asyncio.TimeoutError:
            decision, note = "rejected", "no decision before timeout"
            store.insert("approvals", {"id": store.new_id("ap"), "run_id": run.id, "patch_id": run.patch_id,
                                       "decision": "rejected", "note": note, "ts": time.time()})
            store.update("patches", "id", run.patch_id, approval_status="rejected")
        finally:
            run.waiting, run._approval = None, None
        if decision == "changes_requested" and revisions < MAX_REVISIONS:
            revisions += 1
            if note:
                run.notes["blue"].append(note)
            transition(run, S.DEFENDING, "reviewer requested changes")
            continue
        if decision != "approved":
            transition(run, S.PATCH_REJECTED, note or "rejected")
            return await _finish(run)
        break

    transition(run, S.PATCHING)
    try:
        applied = patcher.apply(run.id, run.patch_id, run.paths["work"])
        store.update("patches", "id", run.patch_id, applied_hash=applied)
        emit(run, "sandbox", "patch", f"Patch applied to the sandbox working copy only (sha256 {applied}).", ok=True)
    except (patcher.PatchError, OSError) as e:
        emit(run, "sandbox", "patch", f"Patch could not be applied: {e}", ok=False)
        transition(run, S.PATCH_FAILED, str(e))
        return await _finish(run)

    # ---- Retest
    transition(run, S.RETESTING)
    agent_status(run, "red", "running", "re-running the original proof against the patched copy")
    spec["token"] = "VG" + secrets.token_hex(6)
    retest = await sandbox.run(run.id, "proof", run.paths["work"], spec, is_demo=run.is_demo, label="retest proof")
    _emit_test(run, "red", retest)
    retry = None
    retry_payload = custom_payload
    if run.mode == "participate" and run.side == "red":
        act = await wait_human(run, "red_retest", "Red, the patch is in. Try a different payload against the patched "
                               "copy, or let the retest finish.")
        if act and act.get("payload"):
            retry_payload = act["payload"][:300]
    if retry_payload:
        retry = await sandbox.run(run.id, "proof", run.paths["work"], {**spec, "custom_payload": retry_payload},
                                  is_demo=run.is_demo, label="retest proof (human payload)")
        _emit_test(run, "human", retry)
    agent_status(run, "red", "completed", "retest done")
    agent_status(run, "blue", "running", "running regression checks")
    benign = await sandbox.run(run.id, "benign", run.paths["work"], spec, is_demo=run.is_demo, label="retest benign call")
    _emit_test(run, "blue", benign)
    regression = await sandbox.run(run.id, "regression", run.paths["work"], is_demo=run.is_demo,
                                   label="retest regression suite")
    _emit_test(run, "blue", regression)

    proofs = [retest] + ([retry] if retry else [])
    if any(p["outcome"] == "pass" for p in proofs):
        final, why = S.UNRESOLVED, "the original issue still reproduces"
    elif any(p["outcome"] == "inconclusive" for p in proofs) or benign["outcome"] == "inconclusive":
        final, why = S.INCONCLUSIVE, "a retest could not run"
    elif benign["outcome"] == "fail" or regression["outcome"] == "fail":
        final, why = S.UNRESOLVED, "the patch broke expected behaviour"
    elif regression["outcome"] == "inconclusive" and run.paths and not _has_tests(run):
        final, why = S.COMPLETED, "no project tests found; benign call check passed"
    elif regression["outcome"] == "inconclusive":
        final, why = S.INCONCLUSIVE, "regression suite could not run"
    else:
        final, why = S.COMPLETED, "proof no longer reproduces and regression checks pass"
    new_status = {"COMPLETED": "fixed", "UNRESOLVED": "unresolved"}.get(final.value, run.finding["status"])
    store.update("findings", "id", run.finding["id"], status=new_status)
    agent_status(run, "blue", "completed" if final == S.COMPLETED else "failed", why)
    transition(run, final, why)
    pointer(run, f"Retest outcome: {report.OUTCOME_TEXT[final.value]}", retest["id"])
    await _finish(run)


def _has_tests(run: Run) -> bool:
    p = Path(run.paths["work"])
    return any(p.rglob("test_*.py")) or any(p.rglob("*_test.py"))


async def _defend(run: Run, revision: int) -> tuple[dict | None, str]:
    f = run.finding
    work = run.paths["work"]
    file_text = patcher.read(work, f["file"])
    patch, author, res = None, "blue-agent", None
    if run.mode == "participate" and run.side == "blue":
        if "blue" in run.backup:
            await _backup_say(run)
        act = await wait_human(run, "blue_patch",
                               "Your move, Blue: write your own fix for the highlighted lines, add a suggestion "
                               "for the Blue Agent, or let it propose a patch.")
        if act and act.get("suggestion"):
            run.notes["blue"].append(act["suggestion"][:500])
        if act and act.get("replacement"):
            try:
                p = patcher.from_replacement(work, f["file"], int(act.get("line_start", f["line_start"])),
                                             int(act.get("line_end", f["line_end"])), act["replacement"][:3000],
                                             f.get("category") or "command-injection")
                patch, author = p, "human"
                emit(run, "human", "info", "Participant wrote the patch.")
            except (patcher.PatchError, ValueError) as e:
                emit(run, "blue", "info", f"Your patch was rejected by the validator ({e}); the Blue Agent will propose one.",
                     ok=False)
    agent_status(run, "blue", "running", "analysing root cause and drafting a patch")
    if patch is None:
        res, patch, err = await agents.blue_defend(f, file_text, f["evidence"] or {}, run.budget, run.notes["blue"], work)
        if res:
            emit(run, "blue", "claim", f"Root cause: {res.data.get('root_cause', '')}",
                 data={**res.data, "label": label_agent(res)})
        if not patch:
            emit(run, "blue", "info", f"No patch: {err}", ok=False)
            agent_status(run, "blue", "failed", "no patch")
            return None, ""
    pid = store.new_id("pa")
    store.insert("patches", {"id": pid, "run_id": run.id, "finding_id": f["id"], "files": [patch["file"]],
                             "diff": patch["diff"],
                             "explanation": (res.data.get("root_cause") if res else "Participant patch") or "",
                             "author": author, "approval_status": "pending", "applied_hash": None,
                             "data": {"file": patch["file"], "new_text": patch["new_text"], "base_text": file_text,
                                      "risks": (res.data.get("risks") if res else []), "revision": revision,
                                      "live": bool(res and res.live)},
                             "ts": time.time()})
    run.patch_id = pid
    emit(run, "blue", "patch", f"Proposed patch {pid} ({author}).", data={"patch_id": pid, "diff": patch["diff"],
                                                                          "risks": res.data.get("risks") if res else []})
    agent_status(run, "blue", "waiting", "patch awaiting approval")
    return patch, label_agent(res) if res else "human"


def _emit_test(run: Run, agent: str, t: dict) -> None:
    label = (t["data"] or {}).get("label", t["kind"])
    where = "sandbox" if t["sandboxed"] else ("UNSANDBOXED DEV RUN" if t["env_id"] == "UNSANDBOXED-DEV" else "not run")
    meaning = {
        "proof": {"pass": "REPRODUCED", "fail": "not reproduced", "inconclusive": "INCONCLUSIVE"},
        "benign": {"pass": "normal input still works", "fail": "normal input broke", "inconclusive": "INCONCLUSIVE"},
        "regression": {"pass": "tests pass", "fail": "tests FAIL", "inconclusive": "INCONCLUSIVE"},
    }.get(t["kind"], {}).get(t["outcome"], t["outcome"])
    emit(run, agent, "test", f"{label}: {meaning} [{where}, {t['id']}]", ok=t["outcome"] == "pass",
         data={"test_id": t["id"], "kind": t["kind"], "outcome": t["outcome"], "output": t["output"][-1500:],
               "result": (t["data"] or {}).get("result"), "sandboxed": bool(t["sandboxed"])})


async def _finish(run: Run) -> None:
    run.round = "report"
    agent_status(run, "manager", "running", "compiling report from stored evidence")
    draft = report.build_battle_report(run.id)
    facts = {k: draft[k] for k in ("final_state", "outcome", "findings", "unresolved", "scores")}
    facts["findings"] = [{k: v for k, v in f.items() if k != "data_flow"} for f in facts["findings"]]
    facts["templated_summary"] = draft["outcome"]
    res = await agents.manager_summary(facts, run.budget)
    report.build_battle_report(run.id, {"text": res.data["summary"], "label": label_agent(res)})
    emit(run, "manager", "report", "Final report ready.", ok=True)
    agent_status(run, "manager", "completed", "report ready")


# ---------------------------------------------------------------- Repo Check
async def _repo_check(run: Run) -> None:
    if not await _intake(run):
        return
    emit(run, "manager", "info", "Repo Check is static and read-only: repository code is parsed, never executed.")
    transition(run, S.SANDBOX_READY)
    transition(run, S.MANAGER_ANALYSING)
    agent_status(run, "manager", "running", "static analysis")
    scan = await asyncio.to_thread(scanner.scan_repo_check, Path(run.paths["source"]))
    emit(run, "manager", "info", f"Scanned {scan['files_scanned']} files with {len(scan['rules'])} rules; "
         f"{len(scan['findings'])} hit(s).")
    res = await agents.manager_triage(scan["findings"], run.budget)
    for i, f in enumerate(scan["findings"][:30]):
        emit(run, "manager", "finding", f"POTENTIAL {f['kind']} ({f['severity']}) at {f['file']}:{f['line_start']}",
             data={"index": i, **f})
    final = S.CHECK_INCONCLUSIVE if scan["files_scanned"] == 0 else S.CHECK_COMPLETED
    transition(run, final)
    report.build_check_report(run.id, scan, {**res.data, "label": label_agent(res)} if res.live else None)
    emit(run, "manager", "report", "Repo Check report ready.", ok=True)
    agent_status(run, "manager", "completed", "report ready")
