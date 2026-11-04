"""The containment probe's secret check must flag real secrets and ignore the image's own public variables.

python:3.12-slim sets GPG_KEY (the public key ID used to verify Python releases). It is not a secret, and
reporting it would show a breach on a sandbox that is correctly contained. These tests run the probe as a plain
subprocess, so they need no Docker; only the "secrets in environment" check is read.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

PROBE = Path(__file__).resolve().parent.parent / "vulnigo" / "harness" / "probe.py"
CHECK = "secrets in environment"


def secrets_check(extra_env: dict) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSWORD", "VULTR"))}
    env.update(extra_env)
    out = subprocess.run([sys.executable, str(PROBE)], env=env, capture_output=True, text=True, timeout=60).stdout
    line = next(ln for ln in out.splitlines() if ln.startswith("VG_RESULT "))
    return next(c for c in json.loads(line[len("VG_RESULT "):])["checks"] if c["check"] == CHECK)


def test_the_images_public_gpg_key_id_is_not_reported_as_a_leak():
    assert secrets_check({"GPG_KEY": "7169605F62C751356D054A26A821E680E5FA6305"})["blocked"] is True


def test_a_real_inference_key_is_reported_as_a_leak():
    c = secrets_check({"VULTR_INFERENCE_API_KEY": "not-a-real-key"})
    assert c["blocked"] is False
    assert "VULTR_INFERENCE_API_KEY" in c["detail"]


def test_a_gpg_key_does_not_hide_a_real_secret_next_to_it():
    c = secrets_check({"GPG_KEY": "7169605F62C751356D054A26A821E680E5FA6305", "DB_PASSWORD": "x"})
    assert c["blocked"] is False
    assert "DB_PASSWORD" in c["detail"]
    assert "GPG_KEY" not in c["detail"]


def test_no_secret_like_variables_is_blocked():
    assert secrets_check({})["blocked"] is True
