"""Patch generation, validation and approval-gated application (working copy only)."""
import ast
import difflib
import re
from pathlib import Path

from . import store


class PatchError(Exception):
    pass


def _safe_path(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() not in p.parents:
        raise PatchError(f"path escapes the working copy: {rel}")
    return p


def read(root: str, rel: str) -> str:
    return _safe_path(Path(root), rel).read_text(encoding="utf-8")


def unified_diff(old: str, new: str, rel: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3))


# ---------------------------------------------------------------- deterministic CWE-78 fix
def _fstring_to_argv(node: ast.JoinedStr, src: str) -> str | None:
    """f"wc -c {DIR}/{name}" -> '["wc", "-c", f"{DIR}/{name}"]' (argument list, no shell)."""
    tokens: list[list[str]] = [[]]
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            pieces = re.split(r"(\s+)", part.value)
            for piece in pieces:
                if not piece:
                    continue
                if piece.isspace():
                    if tokens[-1]:
                        tokens.append([])
                else:
                    tokens[-1].append(piece.replace("\\", "\\\\").replace('"', '\\"').replace("{", "{{").replace("}", "}}"))
        elif isinstance(part, ast.FormattedValue):
            seg = ast.get_source_segment(src, part.value)
            if seg is None or part.format_spec is not None:
                return None
            tokens[-1].append("{" + seg + "}")
        else:
            return None
    out = []
    for t in tokens:
        if not t:
            continue
        s = "".join(t)
        out.append(f'f"{s}"' if "{" in s.replace("{{", "").replace("}}", "") else '"' + s.replace("{{", "{").replace("}}", "}") + '"')
    return "[" + ", ".join(out) + "]" if out else None


def _replace_segment(lines: list[str], node: ast.AST, new: str) -> None:
    sl, sc, el, ec = node.lineno - 1, node.col_offset, node.end_lineno - 1, node.end_col_offset
    head, tail = lines[sl][:sc], lines[el][ec:]
    lines[sl:el + 1] = [head + new + tail]


def deterministic_fix(work: str, finding: dict) -> dict | None:
    """Rewrite `subprocess.X(<f-string>, shell=True)` into an argument list without a shell."""
    rel = finding["file"]
    src = read(work, rel)
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == finding["function"]), None)
    if fn is None:
        return None
    call = next((n for n in ast.walk(fn) if isinstance(n, ast.Call) and n.lineno == finding["line_start"]), None)
    if call is None or not call.args or not finding.get("sink", "").startswith("subprocess"):
        return None
    arg = call.args[0]
    target_node = arg
    if isinstance(arg, ast.Name):
        assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and n.lineno < call.lineno
                   and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets)]
        if not assigns:
            return None
        target_node = max(assigns, key=lambda n: n.lineno).value
    if not isinstance(target_node, ast.JoinedStr):
        return None
    argv = _fstring_to_argv(target_node, src)
    if not argv:
        return None
    shell_kw = next(k for k in call.keywords if k.arg == "shell")

    lines = src.splitlines(keepends=False)
    # Edit bottom-up so earlier offsets stay valid: first the shell=True keyword, then the command.
    kw_line = lines[shell_kw.lineno - 1]
    start, end = shell_kw.col_offset, shell_kw.value.end_col_offset  # keyword node spans "shell=True"
    if shell_kw.lineno != shell_kw.value.end_lineno or not kw_line[start:end].replace(" ", "").startswith("shell="):
        return None
    before, after = kw_line[:start], kw_line[end:]
    if after.lstrip().startswith(","):
        after = after.lstrip()[1:].lstrip()
        before = before.rstrip() + " " if before.rstrip().endswith(",") else before
    elif re.search(r",\s*$", before):
        before = re.sub(r",\s*$", "", before)
    lines[shell_kw.lineno - 1] = before + after
    _replace_segment(lines, target_node, argv)
    new = "\n".join(lines) + ("\n" if src.endswith("\n") else "")
    validate(src, new)
    return {
        "file": rel,
        "new_text": new,
        "diff": unified_diff(src, new, rel),
        "explanation": ("Build the command as an argument list and drop shell=True, so the filename is passed "
                        "to the program as a single argument and the shell never parses it. Characters like ; | $() "
                        "and backticks lose their meaning."),
        "risks": ["Behaviour that relied on shell features (globs, pipes, ~ expansion) in this command would change.",
                  "Option injection (a value starting with '-') is not addressed by this change."],
    }


# ---------------------------------------------------------------- validation & application
def from_replacement(work: str, rel: str, line_start: int, line_end: int, replacement: str) -> dict:
    """Build a patch from a model-proposed replacement for an inclusive line range."""
    src = read(work, rel)
    lines = src.splitlines()
    if not (1 <= line_start <= line_end <= len(lines)) or line_end - line_start > 40:
        raise PatchError("replacement range is out of bounds or too large")
    new_lines = lines[:line_start - 1] + replacement.rstrip("\n").splitlines() + lines[line_end:]
    new = "\n".join(new_lines) + ("\n" if src.endswith("\n") else "")
    validate(src, new)
    return {"file": rel, "new_text": new, "diff": unified_diff(src, new, rel)}


def validate(old: str, new: str) -> None:
    if old == new:
        raise PatchError("patch makes no change")
    try:
        ast.parse(new)
    except SyntaxError as e:
        raise PatchError(f"patched file does not parse: {e}") from e
    changed = sum(1 for l in difflib.ndiff(old.splitlines(), new.splitlines()) if l[:1] in "+-")
    if changed > 80:
        raise PatchError("patch is too large for a minimal fix")
    if re.search(r"shell\s*=\s*True", new) and new.count("shell=True") >= old.count("shell=True"):
        raise PatchError("patch keeps shell=True on the vulnerable call")
    for bad in ("import socket", "urllib.request", "requests.", "eval(", "exec("):
        if new.count(bad) > old.count(bad):
            raise PatchError(f"patch introduces disallowed construct: {bad}")


def apply(run_id: str, patch_id: str, work: str) -> str:
    """Apply a stored patch to the working copy. Refuses unless an approval record exists."""
    patch = store.get("patches", patch_id)
    if not patch or patch["run_id"] != run_id:
        raise PatchError("unknown patch")
    approvals = [a for a in store.list_for("approvals", run_id) if a["patch_id"] == patch_id]
    if not approvals or approvals[-1]["decision"] != "approved":
        raise PatchError("refusing to apply: no approval record for this patch")
    data = patch["data"]
    path = _safe_path(Path(work), data["file"])
    current = path.read_text(encoding="utf-8")
    if current != data["base_text"]:
        raise PatchError("working copy changed since the patch was proposed")
    path.write_text(data["new_text"], encoding="utf-8")
    import hashlib
    return hashlib.sha256(data["new_text"].encode()).hexdigest()[:16]
