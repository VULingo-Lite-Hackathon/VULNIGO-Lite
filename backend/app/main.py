import json
import logging
import os
import subprocess
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

log = logging.getLogger("vulnigo")

SERVICE = "vulnigo-lite"
VERSION = "0.1.0"
SANDBOX_BINARY = os.getenv("VULNIGO_SANDBOX_BINARY", "/usr/local/bin/vulnigo-sandbox")
STARTED_AT = time.monotonic()

app = FastAPI(title="VULNIGO Lite", version=VERSION)

_config_cache: tuple[float, dict] | None = None
CACHE_TTL_S = 30


class Health(BaseModel):
    status: str
    service: str
    version: str
    uptime_s: float


def _sandbox_config() -> dict:
    """Ask the program that enforces the limits what it enforces.

    Reading this from the wrapper instead of our own settings means the UI can never
    display a value the sandbox was not actually built with.
    """
    global _config_cache

    now = time.monotonic()
    if _config_cache and now - _config_cache[0] < CACHE_TTL_S:
        return _config_cache[1]

    try:
        completed = subprocess.run(
            ["sudo", "-n", SANDBOX_BINARY, "--print-config"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        payload = {"available": True, **json.loads(completed.stdout)}
    except Exception:
        payload = {"available": False, "reason": "sandbox limits could not be read"}

    _config_cache = (now, payload)
    return payload


@app.get("/health", response_model=Health)
def health() -> Health:
    return Health(
        status="ok",
        service=SERVICE,
        version=VERSION,
        uptime_s=round(time.monotonic() - STARTED_AT, 1),
    )


@app.get("/sandbox/config")
def sandbox_config() -> JSONResponse:
    return JSONResponse(_sandbox_config())


@app.exception_handler(Exception)
async def unhandled(request, exc):
    # Log the real failure, return a bland one. An exception message can carry a
    # repository path, a command, or a credential an agent put in the text -- none of
    # those belong in a public response, and hiding them from the log too would leave
    # the team debugging a 500 with no trace.
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"status": "error", "service": SERVICE})
