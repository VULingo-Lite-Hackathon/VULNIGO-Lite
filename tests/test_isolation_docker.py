"""What a hostile program can and cannot do inside the real sandbox container (Day 4: isolation, network, limits).

Each test runs a small Python program through the backend's own `_docker_cmd`, so the flags under test are the
flags production uses. Needs a Docker daemon and the vulnigo-sandbox image; skipped without them.
Run only these:  pytest tests/test_isolation_docker.py -m docker

Docker lowers risk; it is not an absolute guarantee. These tests show the configured limits hold on the machine
they ran on. They do not prove the host kernel or Docker daemon is free of escapes.
"""
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from vulnigo import sandbox

pytestmark = pytest.mark.docker


def _docker_ready() -> bool:
    try:
        return asyncio.run(sandbox.docker_available())
    except Exception:
        return False


if not _docker_ready():
    pytest.skip("needs a Docker daemon and the vulnigo-sandbox:latest image", allow_module_level=True)


_MINE: set[str] = set()  # containers this module started; a backend or another test run may own other sbx_ ones


def sandbox_containers() -> list[str]:
    left = []
    for _ in range(10):
        ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=sbx_", "--format", "{{.Names}}"],
                            capture_output=True, text=True)
        assert ps.returncode == 0, ps.stderr  # a failing `docker ps` must not read as "nothing left"
        left = [n for n in ps.stdout.split() if n in _MINE]
        if not left:
            break
        time.sleep(0.5)
    return left


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "hello.txt").write_text("hello\n")
    # pytest's tmp dirs are 0700; the container runs as uid 65534 and sees the bind mount's host modes on Linux.
    os.chmod(tmp_path, 0o755)
    os.chmod(d, 0o755)
    os.chmod(d / "hello.txt", 0o644)
    return d


def run_in_sandbox(code_dir: Path, program: str, timeout: int = 30):
    name = "sbx_" + os.urandom(4).hex()
    _MINE.add(name)
    cmd =sandbox._docker_cmd(name, str(code_dir), ["python", "-c", program])
    return asyncio.run(sandbox._exec(cmd, None, None, timeout, name))


def facts(code_dir: Path, program: str, timeout: int = 30) -> dict:
    code, out, timed_out, truncated = run_in_sandbox(code_dir, program, timeout)
    assert not timed_out and not truncated, out[-300:]
    lines = [ln for ln in out.splitlines() if ln.startswith("{")]
    assert lines, out[-500:]
    return json.loads(lines[-1])


PROGRAM = r"""
import json, os, socket, subprocess, shutil
r = {}
r["uid"], r["gid"] = os.getuid(), os.getgid()
st = open("/proc/self/status").read()
r["cap_bnd"] = [l.split()[1] for l in st.splitlines() if l.startswith("CapBnd")][0]
r["no_new_privs"] = [l.split()[1] for l in st.splitlines() if l.startswith("NoNewPrivs")][0]
r["env_keys"] = sorted(os.environ)
r["docker_sock"] = os.path.exists("/var/run/docker.sock")
def can(f):
    try:
        f(); return True
    except (OSError, subprocess.SubprocessError):
        return False
r["write_src"] = can(lambda: open("/src/new.txt", "w").close())
r["write_existing_src"] = can(lambda: open("/src/hello.txt", "a").write("x"))
r["write_root"] = can(lambda: open("/pwned", "w").close())
r["write_etc"] = can(lambda: open("/etc/pwned", "w").close())
r["write_harness"] = can(lambda: open("/harness/pwned", "w").close())
r["write_tmp"] = can(lambda: open("/tmp/ok", "w").write("ok"))
def run_tmp():
    shutil.copy("/bin/true", "/tmp/t"); os.chmod("/tmp/t", 0o755); subprocess.run(["/tmp/t"], check=True)
r["exec_from_tmp"] = can(run_tmp)
def net():
    s = socket.socket(); s.settimeout(2); s.connect(("1.1.1.1", 53))
r["tcp_out"] = can(net)
try:
    socket.getaddrinfo("example.com", 80); r["dns"] = True
except OSError:
    r["dns"] = False
r["ifaces"] = sorted(l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:])
r["setuid_root"] = can(lambda: os.setuid(0))
r["mount"] = can(lambda: subprocess.run(["mount", "-t", "tmpfs", "x", "/mnt"], check=True, capture_output=True))
def opts(mountpoint):
    for line in open("/proc/mounts"):
        f = line.split()
        if f[1] == mountpoint:
            return f[3].split(",")
r["root_opts"], r["tmp_opts"] = opts("/"), opts("/tmp")
def cg(name):
    try:
        return open("/sys/fs/cgroup/" + name).read().strip()
    except OSError:
        return None
r["mem_max"], r["pids_max"], r["cpu_max"] = cg("memory.max"), cg("pids.max"), cg("cpu.max")
print(json.dumps(r))
"""


def _bytes(size: str) -> int:
    return int(size[:-1]) * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[size[-1].lower()]


def test_the_container_is_unprivileged_offline_and_read_only(src):
    r = facts(src, PROGRAM)
    assert (r["uid"], r["gid"]) == (65534, 65534)
    assert int(r["cap_bnd"], 16) == 0  # bounding set empty: no capability can ever be gained (CapEff is 0 for any non-root)
    assert "ro" in r["root_opts"] and "noexec" in r["tmp_opts"] and "nosuid" in r["tmp_opts"]
    assert r["no_new_privs"] == "1"
    assert r["setuid_root"] is False and r["mount"] is False
    assert r["docker_sock"] is False
    assert not [k for k in r["env_keys"] if any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
                and k != "GPG_KEY"]  # GPG_KEY is the python image's public release key id, not a secret
    assert (r["write_src"], r["write_existing_src"], r["write_root"], r["write_etc"], r["write_harness"]) == \
        (False, False, False, False, False)
    assert r["write_tmp"] is True and r["exec_from_tmp"] is False  # tmpfs is writable but noexec
    assert (r["tcp_out"], r["dns"]) == (False, False)
    assert r["ifaces"] == ["lo"]
    # The limits the kernel enforces on this container match the configured ones (cgroup v2 files).
    if r["mem_max"] is None:  # cgroup v1 or a sandboxed runtime (gVisor) without these files: nothing to compare
        pytest.skip("cgroup v2 limit files not visible in this container; flags checked by the other tests")
    assert r["mem_max"] == str(_bytes(sandbox.config.SANDBOX_MEMORY))
    assert r["pids_max"] == sandbox.pids_limit()
    quota, period = (int(v) for v in r["cpu_max"].split())
    assert quota / period == float(sandbox.config.SANDBOX_CPUS)
    assert sandbox_containers() == []


def test_a_memory_bomb_is_stopped_by_the_cap(src):
    code, out, timed_out, truncated = run_in_sandbox(
        src, "b = []\nwhile True:\n    b.append(bytearray(32 * 1024 * 1024))\n", timeout=60)
    assert not timed_out
    assert code == 137, (code, out[-200:])  # SIGKILL from the cgroup OOM killer: the memory cap acted
    assert sandbox_containers() == []


def test_a_fork_bomb_cannot_start_more_processes_than_the_pid_limit(src):
    code, out, timed_out, truncated = run_in_sandbox(src, r"""
import json, os, time
kids = []
try:
    for _ in range(500):
        pid = os.fork()
        if pid == 0:
            time.sleep(5); os._exit(0)
        kids.append(pid)
except OSError:
    pass
n = len(kids)
for p in kids:
    os.kill(p, 9)
print(json.dumps({"forked": n}))
""")
    assert not timed_out and not truncated
    lines = [ln for ln in out.splitlines() if ln.startswith("{")]
    if lines:  # runc: the kernel refuses the extra forks with EAGAIN and the program reports how many it got
        assert 0 < json.loads(lines[-1])["forked"] < int(sandbox.pids_limit())
    else:  # gVisor: crossing the cgroup limit kills the whole sandbox; the bomb is contained and never reads as a pass
        assert code not in (0, None), out[-200:]
    assert sandbox_containers() == []


def test_a_program_that_never_ends_is_killed_at_the_timeout_and_leaves_no_container(src):
    started = time.monotonic()
    code, out, timed_out, truncated = run_in_sandbox(src, "while True: pass", timeout=4)
    assert timed_out and code is None
    assert time.monotonic() - started < 25
    assert sandbox_containers() == []


def test_a_busy_loop_cannot_use_more_than_its_cpu_share(src):
    r = facts(src, r"""
import json, time
t0 = time.monotonic(); c0 = time.process_time()
while time.monotonic() - t0 < 3:
    pass
print(json.dumps({"cpu_s": time.process_time() - c0, "wall_s": time.monotonic() - t0}))
""")
    assert r["cpu_s"] / r["wall_s"] < float(sandbox.config.SANDBOX_CPUS) + 0.15  # one thread, throttled to ~0.5 CPU


def test_endless_output_is_cut_and_the_container_is_gone(src):
    code, out, timed_out, truncated = run_in_sandbox(
        src, "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n", timeout=30)
    assert truncated and not timed_out and code is None
    assert len(out.encode()) <= sandbox.MAX_OUTPUT_BYTES + 200
    assert sandbox_containers() == []


def test_kernel_attack_surface_socket_families_stay_blocked(src):
    # AF_ALG is the entry point of the "Copy Fail" kernel bug (CVE-2026-31431), AF_VSOCK of the Docker Desktop WSL2
    # seccomp bypass (CVE-2026-112917); AF_PACKET and AF_KEY are classic raw-socket bugs. All are blocked by Docker's
    # default seccomp profile and capability drop. An older Docker, a changed profile or `--security-opt seccomp=unconfined`
    # would let them through: this fails then. AF_UNIX/AF_INET/AF_INET6/AF_NETLINK stay open (Python itself needs
    # AF_UNIX for asyncio); that residual surface is closed only by patching the host kernel.
    r = facts(src, r"""
import json, socket
out = {}
for name in ("AF_ALG", "AF_VSOCK", "AF_PACKET", "AF_KEY", "AF_UNIX"):
    fam = getattr(socket, name)
    try:
        socket.socket(fam, socket.SOCK_SEQPACKET if name == "AF_ALG" else socket.SOCK_DGRAM, 0).close()
        out[name] = "created"
    except OSError as e:
        out[name] = "blocked"
print(json.dumps(out))
""")
    assert {k: v for k, v in r.items() if k != "AF_UNIX"} == {"AF_ALG": "blocked", "AF_VSOCK": "blocked",
                                                              "AF_PACKET": "blocked", "AF_KEY": "blocked"}
    assert r["AF_UNIX"] == "created"  # sanity: the probe itself works
    assert sandbox_containers() == []
