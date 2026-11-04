"""Deterministic static checks. Pass/fail decisions never come from model opinion.

* `scan_command_injection` - the one vulnerability class Lite battles support (CWE-78, Python).
* `scan_repo_check` - wider static heuristics for Repo Check (malicious code + likely vulns).
Neither function executes repository code; they only parse/read text.
"""
import ast
import json
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox", "site-packages"}
MAX_FILE_BYTES = 400_000
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}


def iter_files(root: Path, exts: tuple[str, ...] | None = None):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink() or SKIP_DIRS & set(p.relative_to(root).parts):
            continue
        if exts and p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return f"{f.value.id}.{f.attr}"
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_shell_true(call: ast.Call) -> bool:
    return any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
               for k in call.keywords)


def _tainted_names(fn: ast.FunctionDef) -> dict[str, str]:
    """Map variable name -> originating parameter, following simple assignments in source order."""
    params = [a.arg for a in fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls")]
    taint = {p: p for p in params}
    assigns = sorted((n for n in ast.walk(fn) if isinstance(n, ast.Assign)), key=lambda n: n.lineno)
    for node in assigns:
        src = next((taint[n] for n in sorted(_names(node.value)) if n in taint), None)
        if src:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    taint[t.id] = src
    return taint


def _sink_arg(call: ast.Call) -> tuple[str, ast.AST] | None:
    name = _call_name(call)
    if not call.args:
        return None
    mod, _, fn = name.partition(".")
    if name in ("os.system", "os.popen"):
        return name, call.args[0]
    if mod == "subprocess" and fn in SUBPROCESS_FUNCS:
        if fn in ("getoutput", "getstatusoutput") or _is_shell_true(call):
            return name, call.args[0]
    return None


def scan_command_injection(root: Path) -> list[dict]:
    """Find shell-command sinks fed by a function parameter (one-hop taint)."""
    out: list[dict] = []
    for path in iter_files(root, (".py",)):
        rel = path.relative_to(root).as_posix()
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
        lines = src.splitlines()
        top_level = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            taint = _tainted_names(fn)
            params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
            for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                sink = _sink_arg(call)
                if not sink:
                    continue
                sink_name, arg = sink
                if isinstance(arg, ast.Constant):
                    continue
                hit = sorted({taint[n] for n in _names(arg) if n in taint})
                if not hit:
                    continue
                param = hit[0]
                via = [v for v in sorted(_names(arg)) if v in taint and v != param]
                flow = f"parameter `{param}` of {fn.name}()"
                if via:
                    flow += " -> " + " -> ".join(f"`{v}`" for v in via)
                flow += f" -> {sink_name}(..., shell=True)" if sink_name.startswith("subprocess") else f" -> {sink_name}()"
                start, end = call.lineno, getattr(call, "end_lineno", call.lineno)
                out.append({
                    "category": "command-injection",
                    "cwe": "CWE-78",
                    "file": rel,
                    "line_start": start,
                    "line_end": end,
                    "function": fn.name,
                    "param": param,
                    "params": params,
                    "sink": sink_name,
                    "top_level": fn.name in top_level,
                    "data_flow": flow,
                    "snippet": "\n".join(lines[max(0, fn.lineno - 1):end]),
                    "fn_line": fn.lineno,
                })
    return out


# ---------------------------------------------------------------- Repo Check heuristics
_TEXT_EXTS = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".rb", ".php", ".go", ".json",
              ".yml", ".yaml", ".toml", ".cfg", ".ini", ".env", ".txt", ".ps1", ".bat")

LINE_RULES = [
    # (category, kind, severity, regex, explanation)
    ("malicious", "remote-script-exec", "high", r"(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh\b",
     "Downloads a remote script and pipes it straight into a shell."),
    ("malicious", "reverse-shell", "high", r"/dev/tcp/|bash\s+-i\s+>&|nc\s+(-e|-c)\s",
     "Pattern typical of a reverse shell."),
    ("malicious", "obfuscated-exec", "high",
     r"(exec|eval)\s*\(\s*(base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|atob\()",
     "Executes decoded/obfuscated data."),
    ("malicious", "crypto-miner", "high", r"stratum\+tcp://|xmrig|coinhive|cryptonight",
     "Cryptocurrency-mining indicator."),
    ("malicious", "credential-harvest", "high",
     r"(\.ssh/id_rsa|\.aws/credentials|\.git-credentials|Login Data|wallet\.dat)",
     "Reads well-known credential stores."),
    ("malicious", "env-exfiltration", "medium",
     r"(requests|httpx|urllib\.request|fetch)\W.{0,80}(os\.environ|process\.env)",
     "Sends environment variables over the network."),
    ("vulnerability", "unsafe-eval", "medium", r"\beval\s*\(\s*(input|request|sys\.argv|req\.)",
     "Evaluates user-controlled input."),
    ("vulnerability", "unsafe-deserialization", "medium",
     r"pickle\.loads?\(|marshal\.loads\(|yaml\.load\((?![^)]*SafeLoader)",
     "Deserialises data in a way that can execute code."),
    ("vulnerability", "sql-injection", "medium",
     r"\.execute\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\+|\.format))",
     "SQL built by string formatting instead of parameters."),
    ("vulnerability", "hardcoded-secret", "medium",
     r"AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}",
     "Looks like a committed credential or private key."),
    ("vulnerability", "tls-verification-disabled", "low",
     r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED",
     "TLS certificate verification is disabled."),
    ("vulnerability", "debug-enabled", "low", r"app\.run\([^)]*debug\s*=\s*True",
     "Web framework debug mode enabled (can expose a code console)."),
]
_COMPILED = [(c, k, s, re.compile(r, re.I), e) for c, k, s, r, e in LINE_RULES]


def _install_hooks(root: Path) -> list[dict]:
    hits = []
    for pkg in iter_files(root, (".json",)):
        if pkg.name != "package.json":
            continue
        try:
            scripts = json.loads(pkg.read_text(encoding="utf-8", errors="replace")).get("scripts", {}) or {}
        except (ValueError, AttributeError):
            continue
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            cmd = str(scripts.get(hook, ""))
            if re.search(r"curl|wget|node\s+-e|powershell|base64|\bsh\b|bash", cmd, re.I):
                hits.append({"category": "malicious", "kind": "install-hook", "severity": "high",
                             "file": pkg.relative_to(root).as_posix(), "line_start": 1, "line_end": 1,
                             "snippet": f'"{hook}": "{cmd[:200]}"',
                             "explanation": f"npm `{hook}` script runs network/shell commands at install time."})
    for setup in iter_files(root, (".py",)):
        if setup.name != "setup.py":
            continue
        text = setup.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"(os\.system|subprocess\.|urllib\.request|requests\.(get|post))", text)
        if m:
            line = text[:m.start()].count("\n") + 1
            hits.append({"category": "malicious", "kind": "install-hook", "severity": "medium",
                         "file": setup.relative_to(root).as_posix(), "line_start": line, "line_end": line,
                         "snippet": text.splitlines()[line - 1].strip()[:200],
                         "explanation": "setup.py runs commands or network calls when the package is installed."})
    return hits


def scan_repo_check(root: Path) -> dict:
    findings: list[dict] = []
    scanned = 0
    for path in iter_files(root, _TEXT_EXTS):
        scanned += 1
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            for cat, kind, sev, rx, expl in _COMPILED:
                if rx.search(line):
                    findings.append({"category": cat, "kind": kind, "severity": sev, "file": rel,
                                     "line_start": i, "line_end": i, "snippet": line.strip()[:200],
                                     "explanation": expl})
    findings += _install_hooks(root)
    for ci in scan_command_injection(root):
        sink_line = ci["snippet"].splitlines()[-1].strip() if ci["snippet"] else ""
        findings.append({"category": "vulnerability", "kind": "command-injection", "severity": "high",
                         "file": ci["file"], "line_start": ci["line_start"], "line_end": ci["line_end"],
                         "snippet": sink_line[:200],
                         "explanation": "Function parameter reaches a shell command: " + ci["data_flow"]})
    seen, uniq = set(), []
    for f in findings:
        key = (f["file"], f["line_start"], f["kind"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    rules = [k for _, k, *_ in LINE_RULES] + ["install-hook", "command-injection"]
    return {"files_scanned": scanned, "findings": uniq, "rules": rules}
