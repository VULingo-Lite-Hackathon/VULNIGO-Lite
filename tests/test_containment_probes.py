"""Static checks on the containment probes.

rm_root.py tries to delete "/", so it must never be executed on a host: these tests only parse it.
A real run needs a container: `sudo bash sandbox/containment.sh` on the VM.
"""
import ast
from pathlib import Path

PROBES = Path(__file__).resolve().parent.parent / "sandbox" / "probes"


def test_rm_root_error_callback_takes_the_three_arguments_shutil_passes():
    # shutil.rmtree(onerror=f) calls f(func, path, exc_info). A callback with two parameters raises TypeError,
    # the probe exits 1 before it can report anything, and containment.sh shows a false BREACH.
    tree = ast.parse((PROBES / "rm_root.py").read_text(encoding="utf-8"))
    collect = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "collect")
    assert len(collect.args.args) == 3
    uses_it = any(
        isinstance(n, ast.keyword) and n.arg == "onerror" and isinstance(n.value, ast.Name) and n.value.id == "collect"
        for n in ast.walk(tree)
    )
    assert uses_it, "rm_root.py no longer passes collect as onerror; update this test"
