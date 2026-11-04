"""Put the repo root and backend/ on sys.path so `import agents...` and `import app...`
both work when pytest runs from the project root. No test should depend on cwd."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for path in (ROOT, ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
