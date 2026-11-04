"""Repository intake: strict GitHub URL validation, safe clone, snapshot + working copy."""
import asyncio
import hashlib
import os
import re
import shutil
import stat
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from . import config

_SEG = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class IntakeError(Exception):
    pass


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


def _dir_size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file() and not f.is_symlink())


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


async def _git(*args: str, cwd: Path | None = None, timeout: int = 30) -> tuple[int, str]:
    env = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo",
           "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(config.DATA_DIR)}
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise IntakeError(f"git {args[0] if args else ''} timed out after {timeout}s")
    return proc.returncode, out.decode(errors="replace")


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
        code, out = await _git(
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
            "-c", "submodule.recurse=false", "-c", "http.followRedirects=false",
            "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--no-tags",
            canonical + ".git", str(src), timeout=config.CLONE_TIMEOUT)
        if code != 0:
            raise IntakeError("Clone failed (repo missing, private or unreachable): " + out.strip()[-300:])
        code, out = await _git("rev-parse", "HEAD", cwd=src)
        if code != 0:
            raise IntakeError("Could not read commit hash.")
        commit = out.strip()
        _rm(src / ".git")
        if _dir_size(src) > config.MAX_REPO_MB * 1024 * 1024:
            raise IntakeError(f"Repository is larger than {config.MAX_REPO_MB} MB; Lite only supports small repos.")
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
