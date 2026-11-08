import os
import sys
import tempfile
from pathlib import Path

os.environ["VULNIGO_DATA_DIR"] = tempfile.mkdtemp(prefix="vg_test_")
os.environ["VULTR_INFERENCE_API_KEY"] = ""  # tests never call a real model
os.environ["APPROVAL_TIMEOUT"] = "5"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: needs a Docker daemon and the vulnigo-sandbox image; skipped without them")


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_container_sweep(monkeypatch):
    """The once-per-process sweep removes real sbx_ containers. Tests must not touch the developer's Docker;
    tests/test_sandbox_cleanup.py turns it back on explicitly with a fake docker."""
    from vulnigo import sandbox
    monkeypatch.setattr(sandbox, "_swept", True)
