"""Repository intake: strict GitHub URL validation, safe clone, snapshot + working copy."""
import asyncio
import hashlib
import os
import re
import shutil
import signal
import stat
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from . import config

_SEG = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
# How often the clone directory is measured while git runs. It bounds the overshoot: a flood can write
# for one full interval before the check kills it. A shorter interval stops floods sooner but walks the tree more often.
_WATCH_POLL_S = 0.2


class IntakeError(Exception):
    pass


class RepoTooLarge(IntakeError):
    """The clone watchdog stopped a clone that grew past its byte limit."""


def validate_github_url(raw: str) -> str:
    """Return a canonical https://github.com/owner/repo URL or raise IntakeError.

    Only the exact host github.com over https is allowed, which rules out file://, ssh,
    git://, local paths, credentials in the URL and every private-network address.
    """
    raw = (raw or "").strip()
    if not raw:
        raise IntakeError("Enter a GitHub repository URL.")
    if len(raw) > 300:
        raise IntakeError("URL is too long.")
    try:
        u = urlparse(raw)
    except ValueError as e:
        raise IntakeError(f"Not a valid URL: {e}") from e
    if u.scheme != "https":
        raise IntakeError("Only https:// GitHub URLs are accepted (no file://, ssh, git:// or http).")
    if u.username or u.password or "@" in u.netloc:
        raise IntakeError("Credentials in the URL are not allowed.")
    if (u.hostname or "").lower() not in ("github.com", "www.github.com") or u.port not in (None, 443):
        raise IntakeError("Only public repositories on github.com are supported.")
    if u.query or u.fragment:
        raise IntakeError("Remove query strings and fragments from the URL.")
    parts = [p for p in u.path.split("/") if p]
    if len(parts) != 2:
        raise IntakeError("Use the form https://github.com/<owner>/<repo>.")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not (_SEG.match(owner) and _SEG.match(repo)) or owner.startswith(".") or repo in (".", ".."):
        raise IntakeError("Owner or repository name contains unsupported characters.")
    return f"https://github.com/{owner}/{repo}"


# While cloning, .git (the compressed pack) sits next to the checkout, so the watchdog sees more than the final size
# (measured: flask 1.5x, requests 1.7x, numpy 1.3x). It gets this multiple of MAX_REPO_MB; the real limit is checked
# on the checkout alone once .git is removed.
CLONE_WATCH_FACTOR = 2


def _dir_size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file() and not f.is_symlink())


def _watched_size(p: Path) -> int:
    """Size seen by the clone watchdog. A file that vanishes mid-walk (git renames temp packs) counts as 0."""
    try:
        return _dir_size(p)
    except OSError:
        return 0


def _content_hash(p: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(x for x in p.rglob("*") if x.is_file() and "__pycache__" not in x.parts):
        h.update(f.relative_to(p).as_posix().encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def metadata(p: Path) -> dict:
    exts = Counter(f.suffix.lower() for f in p.rglob("*") if f.is_file() and ".git" not in f.parts)
    files = sum(exts.values())
    return {
        "files": files,
        "bytes": _dir_size(p),
        "top_extensions": dict(exts.most_common(6)),
        "python_files": exts.get(".py", 0),
        "has_tests": any(p.glob("tests")) or any(p.rglob("test_*.py")),
    }


def _make_readonly(p: Path) -> None:
    for root, dirs, files in os.walk(p):
        for f in files:
            fp = Path(root, f)
            try:
                fp.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            except OSError:
                pass


def _rm(path: Path) -> None:
    def onerr(func, p, _):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onerror=onerr)


def _git_env() -> dict:
    env = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo",
           "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(config.DATA_DIR)}
    if "SYSTEMROOT" in os.environ:  # Windows git needs it to resolve DNS; nothing else from the host is passed
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


async def _git(*args: str, cwd: Path | None = None, timeout: int = 30) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd, env=_git_env(),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise IntakeError(f"git {args[0] if args else ''} timed out after {timeout}s")
    return proc.returncode, out.decode(errors="replace")


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Kill proc and the children it started, then reap proc.

    git runs helpers (git-remote-https, index-pack) that write into the same directory, so killing
    only git could let them recreate the directory after it was deleted.
    """
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            "taskkill", "/F", "/T", "/PID", str(proc.pid),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await killer.wait()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    await proc.wait()


async def _run_watched(argv: list[str], watch_dir: Path, max_bytes: int, timeout: float, env: dict) -> None:
    """Run a clone command while watching watch_dir. Raises IntakeError and deletes watch_dir on any failure.

    The command and its children are killed if watch_dir grows past max_bytes or the run lasts longer
    than timeout seconds. A non-zero exit is a failure too.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    proc = await asyncio.create_subprocess_exec(
        *argv, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        start_new_session=os.name != "nt")
    comm = asyncio.ensure_future(proc.communicate())  # drains the output so git never blocks on a full pipe
    try:
        while True:
            done, _ = await asyncio.wait({comm}, timeout=_WATCH_POLL_S)
            if done:
                break
            # Walking the tree blocks, so it runs in a thread instead of stalling the event loop.
            if await asyncio.to_thread(_watched_size, watch_dir) > max_bytes:
                raise RepoTooLarge(f"Repository is larger than {max_bytes // (1024 * 1024)} MB; "
                                   "Lite only supports small repos.")
            if loop.time() >= deadline:
                raise IntakeError(f"git clone timed out after {timeout}s")
        out, _ = comm.result()
        if proc.returncode != 0:
            raise IntakeError("Clone failed (repo missing, private or unreachable): "
                              + out.decode(errors="replace").strip()[-300:])
    except BaseException:
        comm.cancel()
        await _kill_tree(proc)
        _rm(watch_dir)
        raise


async def prepare(run_id: str, repo_url: str | None) -> dict:
    """Fetch the repo into WORK_DIR/run_id/source (snapshot) and .../work (writable copy).

    No repository code is executed here: clone only, with hooks, submodules, symlinks and
    non-https protocols disabled.
    """
    base = config.WORK_DIR / run_id
    _rm(base)
    src, work = base / "source", base / "work"
    base.mkdir(parents=True)

    if repo_url is None:
        shutil.copytree(config.DEMO_REPO_DIR, src, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        commit = "content-sha256:" + _content_hash(src)[:16]
        label = "Prepared demo repository (FileDesk)"
    else:
        canonical = validate_github_url(repo_url)
        try:
            await _run_watched(
                ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                 "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
                 "-c", "submodule.recurse=false", "-c", "http.followRedirects=false",
                 "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--no-tags",
                 canonical + ".git", str(src)],
                src, CLONE_WATCH_FACTOR * config.MAX_REPO_MB * 1024 * 1024, config.CLONE_TIMEOUT, _git_env())
        except RepoTooLarge as e:  # the watchdog's limit is CLONE_WATCH_FACTOR x the real one: name the real one
            raise IntakeError(f"Repository is larger than {config.MAX_REPO_MB} MB; Lite only supports small repos.") from e
        try:
            code, out = await _git("rev-parse", "HEAD", cwd=src)
            if code != 0:
                raise IntakeError("Could not read commit hash.")
            commit = out.strip()
            _rm(src / ".git")
            if _dir_size(src) > config.MAX_REPO_MB * 1024 * 1024:
                raise IntakeError(f"Repository is larger than {config.MAX_REPO_MB} MB; Lite only supports small repos.")
        except BaseException:
            _rm(src)
            raise
        label = canonical.removeprefix("https://github.com/")

    shutil.copytree(src, work)
    _make_readonly(src)
    return {"source": str(src), "work": str(work), "commit_hash": commit, "label": label, "meta": metadata(src)}


def cleanup(run_id: str, keep_work: bool = False) -> None:
    base = config.WORK_DIR / run_id
    if keep_work:
        _rm(base / "source")
    else:
        _rm(base)
