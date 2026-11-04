"""Containment probe. Runs INSIDE the sandbox and tries things that must be blocked.

Every check reports what actually happened; the backend shows this as the containment moment.
"""
import json
import os
import socket


def attempt(name, fn):
    try:
        detail = fn()
        return {"check": name, "blocked": False, "detail": str(detail)[:200]}
    except Exception as e:
        return {"check": name, "blocked": True, "detail": f"{type(e).__name__}: {e}"[:200]}


def net_connect():
    s = socket.create_connection(("1.1.1.1", 443), timeout=3)
    s.close()
    return "connected to 1.1.1.1:443"


def dns():
    return socket.gethostbyname("github.com")


def write_source():
    with open(os.environ.get("VG_SRC", "/src") + "/vulnigo_write_test", "w") as f:
        f.write("x")
    return "wrote into source snapshot"


def docker_socket():
    if os.path.exists("/var/run/docker.sock"):
        return "docker.sock is visible"
    raise FileNotFoundError("no docker socket mounted")


def secrets_in_env():
    leaked = [k for k in os.environ if any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "VULTR"))]
    if leaked:
        return "secret-like env vars present: " + ", ".join(leaked)
    raise PermissionError("no secret-like environment variables")


def root_user():
    if os.getuid() == 0:
        return "running as root"
    raise PermissionError(f"uid={os.getuid()} (non-root)")


def write_root_fs():
    with open("/etc/vulnigo_test", "w") as f:
        f.write("x")
    return "wrote to /etc"


checks = [
    attempt("outbound network (1.1.1.1:443)", net_connect),
    attempt("DNS lookup (github.com)", dns),
    attempt("write to source snapshot", write_source),
    attempt("write to container root filesystem", write_root_fs),
    attempt("host Docker socket", docker_socket),
    attempt("secrets in environment", secrets_in_env),
    attempt("root privileges", root_user),
]
print("VG_RESULT " + json.dumps({"checks": checks, "all_blocked": all(c["blocked"] for c in checks)}))
