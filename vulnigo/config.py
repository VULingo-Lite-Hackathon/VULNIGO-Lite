"""Settings come from environment variables (backend process only, never the sandbox)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_dotenv()

DATA_DIR = Path(os.getenv("VULNIGO_DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "vulnigo.sqlite"
WORK_DIR = DATA_DIR / "work"
DEMO_REPO_DIR = ROOT / "demo_repo"
DEMO_REPO_ID = "demo"

INFERENCE_KEY = os.getenv("VULTR_INFERENCE_API_KEY", "")
INFERENCE_BASE_URL = os.getenv("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/")
RED_MODEL = os.getenv("RED_MODEL", "")
BLUE_MODEL = os.getenv("BLUE_MODEL", "")
MANAGER_MODEL = os.getenv("MANAGER_MODEL", "")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))
LLM_CALL_BUDGET = int(os.getenv("LLM_CALL_BUDGET", "12"))  # per battle
# Reasoning models spend completion tokens "thinking" before the JSON; with a tight max_tokens the JSON gets cut.
# Agents need a short structured answer, so thinking is off by default (the deterministic tests decide outcomes anyway).
LLM_THINKING = os.getenv("LLM_THINKING", "0") == "1"
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "3000"))

SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "vulnigo-sandbox:latest")
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "30"))
SANDBOX_MEMORY = os.getenv("SANDBOX_MEMORY", "256m")
SANDBOX_CPUS = os.getenv("SANDBOX_CPUS", "0.5")
SANDBOX_PIDS = os.getenv("SANDBOX_PIDS", "64")
SANDBOX_RUNTIME = os.getenv("SANDBOX_RUNTIME", "")  # e.g. "runsc" for gVisor
# Dev only: run the *bundled demo repo* harness without Docker. Every result is labelled UNSANDBOXED.
ALLOW_UNSANDBOXED_DEMO = os.getenv("VULNIGO_ALLOW_UNSANDBOXED_DEMO", "") == "1"

MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "50"))
CLONE_TIMEOUT = int(os.getenv("CLONE_TIMEOUT", "60"))
APPROVAL_TIMEOUT = int(os.getenv("APPROVAL_TIMEOUT", "1800"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
WORK_DIR.mkdir(parents=True, exist_ok=True)
