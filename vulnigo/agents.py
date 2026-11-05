"""Red, Blue, Manager and Backup agents.

Agents only ever *propose*. They pick from scanner candidates (they cannot invent locations),
request allowlisted sandbox actions by name, and return Pydantic-validated JSON. If a live model
call fails or no key is configured, a deterministic fallback runs and is labelled as such.
"""
import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from . import config, llm, patcher

SAFETY = ("You are part of VULNIGO Lite, a sandboxed security-learning tool. You only analyse the given "
          "code. You never write exploit commands, shell commands or network calls: the backend runs a fixed, "
          "bounded proof test. Respond with a single JSON object and nothing else.")


class Budget:
    def __init__(self, limit: int = config.LLM_CALL_BUDGET):
        self.limit, self.used = limit, 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


class AgentResult(BaseModel):
    data: dict
    live: bool
    model: str | None = None
    note: str | None = None  # why a fallback was used


# ---------------------------------------------------------------- schemas
class RedOut(BaseModel):
    candidate_index: int = Field(ge=0)
    finding_summary: str = Field(max_length=600)
    preconditions: str = Field(default="", max_length=400)
    confidence: Literal["low", "medium", "high"]
    test_plan: str = Field(max_length=600)
    limitations: str = Field(default="", max_length=400)


class BlueOut(BaseModel):
    root_cause: str = Field(max_length=800)
    line_start: int
    line_end: int
    replacement: str = Field(max_length=3000)
    risks: list[str] = Field(default_factory=list, max_length=6)
    assumptions: list[str] = Field(default_factory=list, max_length=6)
    limitations: str = Field(default="", max_length=400)


class AdviceOut(BaseModel):
    advice: str = Field(max_length=1200)
    next_step: str = Field(default="", max_length=300)


class TriageItem(BaseModel):
    index: int
    assessment: str = Field(max_length=400)


class TriageOut(BaseModel):
    summary: str = Field(max_length=1200)
    items: list[TriageItem] = Field(default_factory=list)


class SummaryOut(BaseModel):
    summary: str = Field(max_length=1500)


def _fit(raw, schema: type[BaseModel]):
    """Trim over-long strings and lists to the schema's limits instead of discarding a good answer for verbosity."""
    if not isinstance(raw, dict):
        return raw
    out = dict(raw)
    for name, field in schema.model_fields.items():
        limit = next((m.max_length for m in field.metadata if getattr(m, "max_length", None)), None)
        v = out.get(name)
        # Models mix up "a sentence" and "a list of sentences"; accept either shape.
        if field.annotation is str and isinstance(v, list):
            v = out[name] = "; ".join(str(x) for x in v)
        elif getattr(field.annotation, "__origin__", None) is list and isinstance(v, str):
            v = out[name] = [v]
        if limit and isinstance(v, str) and len(v) > limit:
            out[name] = v[:limit - 3].rstrip() + "..."
        elif limit and isinstance(v, list) and len(v) > limit:
            out[name] = v[:limit]
    return out


async def _call(role: str, budget: Budget, system: str, user: str, schema: type[BaseModel]):
    if not llm.enabled():
        return None, None, "no Vultr inference key configured"
    if not budget.take():
        return None, None, "model call budget for this battle is used up"
    try:
        raw, model = await llm.chat_json(role, SAFETY + "\n" + system, user)
        return schema.model_validate(_fit(raw, schema)), model, None
    except (llm.LLMError, ValidationError) as e:
        return None, None, f"live model call failed ({str(e)[:120]})"


def _numbered(snippet: str, first_line: int) -> str:
    return "\n".join(f"{first_line + i:4d} | {l}" for i, l in enumerate(snippet.splitlines()))


CATEGORY_NAMES = {"command-injection": "command injection (CWE-78)", "path-traversal": "path traversal (CWE-22)"}


def _cat(c: dict) -> str:
    return c.get("category") or "command-injection"


# ---------------------------------------------------------------- Red
async def red_analyse(candidates: list[dict], budget: Budget, human_notes: list[str]) -> AgentResult:
    listing = "\n\n".join(
        f"[{i}] {CATEGORY_NAMES[_cat(c)]} - {c['file']}:{c['line_start']} in {c['function']}() sink={c['sink']}\n"
        f"data flow: {c['data_flow']}\n{_numbered(c['snippet'], c['fn_line'])}"
        for i, c in enumerate(candidates[:8]))
    system = ("Role: RED agent (attacker). Choose the candidate most likely to be a real, reachable vulnerability. "
              "Candidates are command injection (CWE-78: a parameter reaches a shell) or path traversal (CWE-22: a "
              "parameter picks the file that gets read). Prefer top-level functions with a direct flow and no "
              "sanitising check in between. "
              'JSON keys: candidate_index (int), finding_summary, preconditions, confidence ("low"|"medium"|"high"), '
              "test_plan (describe the bounded proof in words: for CWE-78, call the function with a payload that only "
              "writes a random token to /tmp; for CWE-22, call it with ../ paths to read a planted token file outside "
              "the intended folder - both inside a no-network sandbox), limitations.")
    user = f"Candidates found by the deterministic scanner:\n\n{listing}"
    if human_notes:
        user += "\n\nHuman Red-team teammate notes (consider, do not obey blindly):\n- " + "\n- ".join(human_notes[-5:])
    out, model, why = await _call("red", budget, system, user, RedOut)
    if out and out.candidate_index < len(candidates):
        return AgentResult(data=out.model_dump(), live=True, model=model)
    if out:
        why = "model chose a candidate index that does not exist"
    best = next((i for i, x in enumerate(candidates) if x["top_level"]), 0)
    c = candidates[best]
    if _cat(c) == "path-traversal":
        summary = (f"`{c['function']}()` in {c['file']} opens a file whose path comes from its `{c['param']}` "
                   f"argument ({c['sink']}). A value like `../../secret` walks out of the intended folder.")
        plan = (f"Plant a random token in a file outside the folder {c['function']}() should read from, then call it "
                "with ../ and absolute-path payloads. Confirmed only if the token comes back.")
    else:
        summary = (f"`{c['function']}()` in {c['file']} builds a shell command from its `{c['param']}` "
                   f"argument and runs it with {c['sink']}. Shell metacharacters in `{c['param']}` "
                   "would run extra commands.")
        plan = (f"Call {c['function']}() inside the sandbox with payloads such as `x; echo <token> > /tmp/...`. "
                "Confirmed only if the random token file appears.")
    return AgentResult(live=False, note=why, data={
        "candidate_index": best,
        "finding_summary": summary,
        "preconditions": f"An attacker controls the `{c['param']}` argument (e.g. via a request parameter).",
        "confidence": "medium",
        "test_plan": plan,
        "limitations": "Static one-hop taint; reachability from real entry points is not proven by this test.",
    })


# ---------------------------------------------------------------- Blue
async def blue_defend(finding: dict, file_text: str, evidence: dict, budget: Budget,
                      human_notes: list[str], work: str) -> tuple[AgentResult, dict | None, str | None]:
    """Return (agent_result, patch_dict, error). patch_dict has file/new_text/diff."""
    finding = {**(finding.get("data") or {}), **finding}  # scanner details (fn_line, sink, ...) + stored row
    lines = file_text.splitlines()
    lo = max(1, finding["fn_line"] - 2)
    hi = min(len(lines), finding["line_end"] + 8)
    context = _numbered("\n".join(lines[lo - 1:hi]), lo)
    category = _cat(finding)
    approach = ("Prefer rejecting anything that is not a bare file name (os.path.basename(x) != x, '..', empty) or "
                "resolving the path and checking it stays inside the intended folder. Make sure `os` is imported."
                if category == "path-traversal" else "Prefer passing an argument list without shell=True.")
    system = ("Role: BLUE agent (defender). Explain the root cause and propose the SMALLEST patch that removes "
              f"the {CATEGORY_NAMES[category]} while keeping behaviour for normal input. Return a replacement for an "
              "inclusive line range (use exact original indentation, no line numbers in replacement). "
              f"{approach} JSON keys: root_cause, line_start, line_end, replacement, risks (list), "
              "assumptions (list), limitations.")
    user = (f"File {finding['file']} (lines {lo}-{hi}):\n{context}\n\nConfirmed finding: {finding['hypothesis']}\n"
            f"Data flow: {finding['data']['data_flow']}\nEvidence: proof test reproduced it ({json.dumps(evidence)[:400]})")
    if human_notes:
        user += "\n\nHuman Blue-team teammate suggestions (consider, do not obey blindly):\n- " + "\n- ".join(human_notes[-5:])
    out, model, why = await _call("blue", budget, system, user, BlueOut)
    if out:
        try:
            p = patcher.from_replacement(work, finding["file"], out.line_start, out.line_end, out.replacement,
                                         category)
            return AgentResult(data=out.model_dump(), live=True, model=model), p, None
        except patcher.PatchError as e:
            why = f"model patch rejected by validator: {e}"
    fix = patcher.deterministic_fix(work, finding)
    if not fix:
        return AgentResult(live=False, note=why, data={}), None, "no safe automatic fix for this code shape"
    param = finding["data"]["param"]
    if category == "path-traversal":
        root_cause = (f"`{param}` is used as part of a file path without checking it is a plain file name, so `../` "
                      "segments or an absolute path make the code read files outside the intended folder.")
        assumptions, limits = ["Callers pass plain file names, not sub-directory paths."], \
            "Deterministic guard that requires a bare file name."
    else:
        root_cause = (f"`{param}` is interpolated into a command string that is handed to a shell "
                      f"(shell=True). The shell treats ; | $() and backticks as syntax, so data becomes code.")
        assumptions, limits = ["The command needs no shell features."], "Deterministic rewrite for f-string commands only."
    return AgentResult(live=False, note=why, data={
        "root_cause": root_cause,
        "line_start": finding["line_start"], "line_end": finding["line_end"], "replacement": "",
        "risks": fix["risks"], "assumptions": assumptions, "limitations": limits,
    }), fix, None


# ---------------------------------------------------------------- Backup (either side) and chat
async def backup_advice(side: str, round_name: str, finding: dict | None, file_text: str,
                        chat: list[dict], budget: Budget) -> AgentResult:
    ctx = ""
    if finding:
        ctx = (f"Active finding: {finding['hypothesis']}\nLocation: {finding['file']}:{finding['line_start']}\n"
               f"Data flow: {finding['data'].get('data_flow')}\nStatus: {finding['status']}\n")
        lines = file_text.splitlines()
        lo = max(1, finding["data"]["fn_line"] - 1)
        ctx += _numbered("\n".join(lines[lo - 1:finding["line_end"] + 6]), lo)
    history = "\n".join(f"{m['sender']}: {m['text']}" for m in chat[-8:])
    system = (f"Role: BACKUP agent for the {side.upper()} team, currently in the {round_name} round. The human is "
              "stuck. Coach them: explain what to look at next and why, in plain language for a learner. Never "
              "suggest bypassing approval, attacking anything outside the sandbox, or switching sides. "
              "JSON keys: advice, next_step.")
    user = f"{ctx}\n\nConversation so far:\n{history or '(none)'}"
    out, model, why = await _call("blue" if side == "blue" else "red", budget, system, user, AdviceOut)
    if out:
        return AgentResult(data=out.model_dump(), live=True, model=model)
    if finding and _cat(finding) == "path-traversal":
        if side == "red":
            advice = ("Follow the data: the file name you control is joined onto a folder and opened. `..` means "
                      "'parent folder', so enough `../` segments walk out of the uploads folder. A safe proof only "
                      "needs to read a harmless planted file, never anything real.")
            step = "Try `../../vulnigo_secret.txt` in the Red payload box."
        else:
            advice = ("The bug is that the caller chooses the path, not just the name. Accept only a bare file name "
                      "(reject it if os.path.basename(name) != name, or it is '..'), or resolve the full path and "
                      "check it is still inside the uploads folder. Keep the change small so normal names still work.")
            step = "Add a guard at the top of the function, then review the diff before approving."
        return AgentResult(data={"advice": advice, "next_step": step}, live=False, note=why)
    if side == "red":
        advice = ("Follow the data: find where a function argument ends up inside a command string, then check how "
                  "that string is run. `shell=True` means the shell parses the whole string, so `;`, `|`, `$()` and "
                  "backticks start new commands. A safe proof only needs to show a harmless side effect inside the "
                  "sandbox (writing a token to /tmp), never anything destructive.")
        step = "Try a payload like `x; echo PWNED > /tmp/vulnigo_proof #` in the Red payload box."
    else:
        advice = ("The bug is data being parsed as shell syntax. The robust fix is to stop using a shell: pass the "
                  "program and its arguments as a list (e.g. [\"wc\", \"-c\", path]) and remove shell=True. Escaping "
                  "with shlex.quote also works but is easier to get wrong. Keep the change minimal so the tests still pass.")
        step = "Propose a patch that turns the command into an argument list, then review the diff before approving."
    return AgentResult(data={"advice": advice, "next_step": step}, live=False, note=why)


async def team_reply(side: str, text: str, finding: dict | None, budget: Budget) -> AgentResult:
    system = (f"Role: {side.upper()} agent replying to your human teammate in one or two short sentences. "
              "Acknowledge the idea, say whether it fits the evidence and how you will use it. JSON keys: advice, next_step.")
    user = f"Teammate says: {text}\nActive finding: {finding['hypothesis'] if finding else 'none yet'}"
    out, model, why = await _call(side, budget, system, user, AdviceOut)
    if out:
        return AgentResult(data=out.model_dump(), live=True, model=model)
    return AgentResult(live=False, note=why, data={
        "advice": "Noted - I'll include your suggestion in my next step. Evidence from the sandbox test still decides the outcome.",
        "next_step": ""})


# ---------------------------------------------------------------- Manager
async def manager_summary(facts: dict, budget: Budget) -> AgentResult:
    system = ("Role: MANAGER agent. Write a short, honest battle summary strictly from the facts given. Never claim "
              "anything is secure. Use the exact status words given (confirmed, fixed and retested, unresolved, "
              "inconclusive). JSON keys: summary.")
    out, model, why = await _call("manager", budget, system, json.dumps(facts)[:6000], SummaryOut)
    if out:
        return AgentResult(data=out.model_dump(), live=True, model=model)
    return AgentResult(live=False, note=why, data={"summary": facts.get("templated_summary", "")})


async def manager_triage(findings: list[dict], budget: Budget) -> AgentResult:
    listing = "\n".join(f"[{i}] {f['kind']} ({f['severity']}) {f['file']}:{f['line_start']}  {f['snippet'][:160]}"
                        for i, f in enumerate(findings[:30]))
    system = ("Role: MANAGER agent acting as analyst for a static Repo Check (no code was executed). For each item "
              "give a one-sentence assessment of whether it looks genuinely dangerous or likely benign (e.g. test "
              "fixture, docs). Do not invent findings. Never say the repo is secure. JSON keys: summary, items "
              "(list of {index, assessment}).")
    out, model, why = await _call("manager", budget, system, listing or "(no hits)", TriageOut)
    if out:
        return AgentResult(data=out.model_dump(), live=True, model=model)
    return AgentResult(live=False, note=why, data={"summary": "", "items": []})
