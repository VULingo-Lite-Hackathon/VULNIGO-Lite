"""Evidence-based report and score arithmetic. Every line cites a stored row."""
import time

from . import store

STATUS_WORDS = {
    "confirmed": "Confirmed",
    "unconfirmed": "Potential / unconfirmed",
    "inconclusive": "Inconclusive",
    "fixed": "Fixed and retested",
    "unresolved": "Unresolved",
}

OUTCOME_TEXT = {
    "COMPLETED": "Fixed and retested: the original proof test no longer reproduces the issue and the regression checks passed.",
    "UNRESOLVED": "Unresolved: after the patch, the issue still reproduces or the patch broke expected behaviour.",
    "INCONCLUSIVE": "Inconclusive: the retest could not produce enough evidence. This is not a pass.",
    "PATCH_REJECTED": "Patch rejected by the human reviewer. No changes were applied. The finding remains open.",
    "PATCH_FAILED": "The approved patch could not be applied to the working copy. The finding remains open.",
    "DEFENSE_INCONCLUSIVE": "No valid patch was produced. The finding remains open.",
    "NO_CONFIRMED_FINDING": "No finding was confirmed by a sandbox test. Nothing detected by the checks that were run - this does not mean the repository is secure.",
    "ATTACK_INCONCLUSIVE": "The attack test could not run or gave insufficient evidence. Inconclusive - not a pass.",
    "FAILED": "The battle could not start (repository intake failed).",
}


def scores(run_id: str, final_state: str) -> dict:
    findings = store.list_for("findings", run_id)
    tests = {t["id"]: t for t in store.list_for("test_runs", run_id)}
    patches = store.list_for("patches", run_id)
    red, blue = [], []
    for f in findings:
        if f["status"] in ("confirmed", "fixed", "unresolved"):
            red.append({"points": 100, "why": f"Confirmed finding {f['id']} ({f['file']}:{f['line_start']})",
                        "evidence": f["test_ref"]})
    retest = [t for t in tests.values() if t["kind"] == "proof" and (t["data"] or {}).get("label", "").startswith("retest")]
    if final_state == "UNRESOLVED" and any(t["outcome"] == "pass" for t in retest):
        t = next(t for t in retest if t["outcome"] == "pass")
        red.append({"points": 50, "why": "Attack still reproduces after the patch", "evidence": t["id"]})
    if final_state == "COMPLETED":
        t = next((t for t in retest if t["outcome"] == "fail"), None)
        blue.append({"points": 100, "why": "Fix verified: original proof no longer reproduces", "evidence": t and t["id"]})
        reg = next((t for t in tests.values() if t["kind"] == "regression" and t["outcome"] == "pass"), None)
        if reg:
            blue.append({"points": 25, "why": "Project regression tests pass on the patched copy", "evidence": reg["id"]})
    for p in patches:
        if p["approval_status"] == "rejected":
            blue.append({"points": -25, "why": f"Patch {p['id']} rejected in review", "evidence": p["id"]})
    return {"red": {"total": sum(x["points"] for x in red), "lines": red},
            "blue": {"total": sum(x["points"] for x in blue), "lines": blue}}


def build_battle_report(run_id: str, manager_summary: dict | None = None) -> dict:
    run = store.get("runs", run_id)
    findings = store.list_for("findings", run_id)
    patches = store.list_for("patches", run_id)
    tests = store.list_for("test_runs", run_id)
    approvals = store.list_for("approvals", run_id)
    events = store.list_for("events", run_id)
    pointers = store.list_for("pointers", run_id)
    state = run["status"]
    unresolved = []
    for f in findings:
        if f["status"] != "fixed":
            unresolved.append(f"{STATUS_WORDS.get(f['status'], f['status'])}: {f['file']}:{f['line_start']} - {f['hypothesis'][:160]}")
    sandboxed = all(t["sandboxed"] for t in tests if t["outcome"] != "inconclusive") if tests else False
    body = {
        "kind": "battle",
        "run_id": run_id,
        "repository": run["repo_label"],
        "commit_hash": run["commit_hash"],
        "mode": run["mode"], "side": run["side"],
        "final_state": state,
        "outcome": OUTCOME_TEXT.get(state, state),
        "manager_summary": manager_summary,
        "findings": [{"id": f["id"], "status": STATUS_WORDS.get(f["status"], f["status"]), "file": f["file"],
                      "lines": [f["line_start"], f["line_end"]], "hypothesis": f["hypothesis"],
                      "data_flow": (f["data"] or {}).get("data_flow"), "evidence": f["test_ref"]} for f in findings],
        "patches": [{"id": p["id"], "author": p["author"], "approval": p["approval_status"], "diff": p["diff"],
                     "applied_hash": p["applied_hash"]} for p in patches],
        "test_runs": [{"id": t["id"], "kind": t["kind"], "label": (t["data"] or {}).get("label"), "outcome": t["outcome"],
                       "exit_code": t["exit_code"], "sandboxed": bool(t["sandboxed"]), "env": t["env_id"],
                       "command": t["command"]} for t in tests],
        "approvals": [{"patch": a["patch_id"], "decision": a["decision"], "note": a["note"], "ts": a["ts"]} for a in approvals],
        "pointers": [{"text": p["text"], "evidence": p["evidence_ref"], "decision": p["decision"]} for p in pointers],
        "unresolved": unresolved,
        "timeline": [{"ts": e["ts"], "agent": e["agent"], "message": e["message"]} for e in events
                     if e["type"] in ("state", "finding", "patch", "test", "approval", "backup")],
        "scores": scores(run_id, state),
        "all_execution_sandboxed": sandboxed,
        "disclaimer": "A successful test of one vulnerability does not certify the repository as secure.",
        "generated_at": time.time(),
    }
    store.upsert_report(run_id, body)
    return body


def build_check_report(run_id: str, scan: dict, triage: dict | None) -> dict:
    run = store.get("runs", run_id)
    assess = {i["index"]: i["assessment"] for i in (triage or {}).get("items", [])}
    items = []
    for i, f in enumerate(scan["findings"]):
        items.append({**f, "grade": "Potential", "assessment": assess.get(i)})
    mal = [x for x in items if x["category"] == "malicious"]
    vul = [x for x in items if x["category"] == "vulnerability"]
    if scan["files_scanned"] == 0:
        verdict = "Inconclusive: no readable source files were found to analyse."
    elif not items:
        verdict = ("Nothing detected by the checks that were run. This is not a statement that the repository "
                   "is secure - only these static rules were applied.")
    else:
        verdict = (f"{len(mal)} possible malicious-code indicator(s) and {len(vul)} likely vulnerability pattern(s) "
                   "found. All are graded Potential: a static read shows the code looks dangerous, not that it is exploitable.")
    body = {
        "kind": "repo_check", "run_id": run_id, "repository": run["repo_label"], "commit_hash": run["commit_hash"],
        "final_state": run["status"], "verdict": verdict, "files_scanned": scan["files_scanned"],
        "rules_applied": scan["rules"], "malicious": mal, "vulnerabilities": vul,
        "manager_summary": (triage or {}).get("summary") or None,
        "executed_code": False,
        "disclaimer": "Repo Check is static and read-only. A clean result does not certify the repository as secure.",
        "generated_at": time.time(),
    }
    store.upsert_report(run_id, body)
    return body
