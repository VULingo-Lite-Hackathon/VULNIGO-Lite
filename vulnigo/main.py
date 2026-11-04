"""FastAPI entry point: REST + Server-Sent Events. The frontend never calls a model directly."""
import asyncio
import json
import time
from collections import defaultdict, deque
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import battle, config, intake, llm, sandbox, store
from .bus import bus
from .state import TERMINAL

app = FastAPI(title="VULNIGO Lite", version="0.1.0")
FRONTEND = config.ROOT / "frontend"

# ---------------------------------------------------------------- simple per-IP rate limit
_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request, limit: int = 6, window: int = 60) -> None:
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()
    q, now = _hits[ip], time.time()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests; slow down.")
    q.append(now)


class CreateBattle(BaseModel):
    repo_url: str | None = Field(default=None, description="GitHub URL; omit for the prepared demo repo")
    mode: Literal["spectator", "participate"] = "spectator"
    side: Literal["red", "blue"] | None = None


class CreateCheck(BaseModel):
    repo_url: str | None = None


class ModeIn(BaseModel):
    mode: Literal["spectator", "participate"]
    side: Literal["red", "blue"] | None = None


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=1000)


class ApprovalIn(BaseModel):
    patch_id: str
    decision: Literal["approved", "rejected", "changes_requested"]
    note: str = Field(default="", max_length=500)


class PointerIn(BaseModel):
    decision: Literal["approved", "dismissed"]


class ActionIn(BaseModel):
    candidate_index: int | None = None
    hypothesis: str | None = Field(default=None, max_length=500)
    payload: str | None = Field(default=None, max_length=300)
    suggestion: str | None = Field(default=None, max_length=500)
    line_start: int | None = None
    line_end: int | None = None
    replacement: str | None = Field(default=None, max_length=3000)
    proceed: bool = False


def _run(run_id: str) -> battle.Run:
    run = battle.RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown or expired run")
    return run


def _snapshot(run_id: str) -> dict:
    row = store.get("runs", run_id)
    if not row:
        raise HTTPException(404, "unknown run")
    run = battle.RUNS.get(run_id)
    rep = store.get("reports", run_id, key="run_id")
    return {
        **row,
        "waiting": run.waiting if run else None,
        "round": run.round if run else "report",
        "backup": sorted(run.backup) if run else [],
        "pending_patch": run.patch_id if run and run.waiting == "approval" else None,
        "findings": store.list_for("findings", run_id),
        "patches": [{k: v for k, v in p.items() if k != "data"} for p in store.list_for("patches", run_id)],
        "test_runs": store.list_for("test_runs", run_id),
        "pointers": store.list_for("pointers", run_id),
        "report": rep["body"] if rep else None,
    }


# ---------------------------------------------------------------- routes
@app.get("/health")
async def health():
    return {"ok": True, "sandbox": await sandbox.docker_available(), "llm": llm.enabled(),
            "unsandboxed_demo_allowed": config.ALLOW_UNSANDBOXED_DEMO}


@app.get("/api/config")
async def get_config():
    models = {}
    if llm.enabled():
        for role in ("red", "blue", "manager"):
            try:
                models[role] = await llm.pick_model(role)
            except Exception as e:
                models[role] = f"unavailable ({type(e).__name__})"
    return {"sandbox": await sandbox.docker_available(), "policy": sandbox.describe_policy(),
            "llm": llm.enabled(), "models": models, "inference_base_url": config.INFERENCE_BASE_URL}


@app.post("/battles")
async def create_battle(body: CreateBattle, request: Request):
    rate_limit(request)
    if body.mode == "participate" and not body.side:
        raise HTTPException(422, "Choose a side (red or blue) to participate.")
    try:
        run = battle.create("battle", body.repo_url, body.mode, body.side if body.mode == "participate" else None)
    except intake.IntakeError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    return {"id": run.id}


@app.post("/repo-checks")
async def create_check(body: CreateCheck, request: Request):
    rate_limit(request)
    try:
        run = battle.create("check", body.repo_url, "repo_check", None)
    except intake.IntakeError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    return {"id": run.id}


@app.get("/battles/{run_id}")
@app.get("/repo-checks/{run_id}")
async def get_run(run_id: str):
    return _snapshot(run_id)


@app.get("/runs")
async def runs():
    return store.recent_runs()


@app.post("/battles/{run_id}/mode")
async def set_mode(run_id: str, body: ModeIn):
    run = _run(run_id)
    if run.kind != "battle" or run.state.value not in ("CREATED", "REPOSITORY_VALIDATING", "SANDBOX_READY"):
        raise HTTPException(409, "Mode can only change before the attack round starts; teams never change mid-battle.")
    if body.mode == "participate" and not body.side:
        raise HTTPException(422, "Choose a side.")
    run.mode, run.side = body.mode, (body.side if body.mode == "participate" else None)
    store.update("runs", "id", run.id, mode=run.mode, side=run.side)
    battle.emit(run, "manager", "info", f"Mode set to {run.mode}" + (f" ({run.side.upper()} team)" if run.side else ""))
    return {"ok": True}


@app.post("/battles/{run_id}/messages")
async def message(run_id: str, body: MessageIn):
    run = _run(run_id)
    if run.state in TERMINAL:
        raise HTTPException(409, "battle is over")
    asyncio.create_task(battle.add_message(run, body.text))
    return {"ok": True}


@app.post("/battles/{run_id}/backup")
async def backup(run_id: str):
    run = _run(run_id)
    try:
        await battle.request_backup(run)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"ok": True}


@app.post("/battles/{run_id}/approvals")
async def approve(run_id: str, body: ApprovalIn):
    run = _run(run_id)
    try:
        battle.submit_approval(run, body.patch_id, body.decision, body.note)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"ok": True}


@app.post("/battles/{run_id}/actions")
async def action(run_id: str, body: ActionIn):
    run = _run(run_id)
    if run.mode != "participate":
        raise HTTPException(409, "Only participants take turns.")
    try:
        battle.submit_human(run, body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"ok": True}


@app.post("/battles/{run_id}/pointers/{pointer_id}")
async def pointer_decision(run_id: str, pointer_id: str, body: PointerIn):
    p = store.get("pointers", pointer_id)
    if not p or p["run_id"] != run_id:
        raise HTTPException(404, "unknown pointer")
    store.update("pointers", "id", pointer_id, decision=body.decision)
    run = battle.RUNS.get(run_id)
    if run:
        battle.emit(run, "human", "pointer_decision", f"Pointer {body.decision}: {p['text'][:120]}",
                    data={"pointer_id": pointer_id, "decision": body.decision})
    return {"ok": True}


@app.get("/battles/{run_id}/report")
@app.get("/repo-checks/{run_id}/report")
async def get_report(run_id: str):
    rep = store.get("reports", run_id, key="run_id")
    if not rep:
        raise HTTPException(404, "report not ready")
    return rep["body"]


@app.get("/battles/{run_id}/events")
@app.get("/repo-checks/{run_id}/events")
async def events(run_id: str, request: Request):
    if not store.get("runs", run_id):
        raise HTTPException(404, "unknown run")

    async def gen():
        q = bus.subscribe(run_id)
        try:
            last = 0
            for e in store.list_for("events", run_id, order="id"):
                last = e["id"]
                yield f"id: {e['id']}\ndata: {json.dumps(e)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    e = await asyncio.wait_for(q.get(), 15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if e["id"] <= last:
                    continue
                yield f"id: {e['id']}\ndata: {json.dumps(e)}\n\n"
        finally:
            bus.unsubscribe(run_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

    @app.get("/")
    async def index():
        return FileResponse(FRONTEND / "index.html")
