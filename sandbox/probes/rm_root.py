"""Try to destroy the container's own filesystem. Success means nothing was lost."""
import os
import shutil
import sys

refused = []


def collect(func, path, exc_info):
    # shutil.rmtree calls onerror(func, path, exc_info): three arguments.
    refused.append(f"{os.path.basename(str(path))}: {exc_info[1]}")


try:
    shutil.rmtree("/", onerror=collect)
except OSError as exc:
    refused.append(f"rmtree aborted: {exc}")

survived = os.path.exists("/etc/passwd") and os.path.exists(sys.executable)
print(f"destructions refused: {len(refused)}", flush=True)
if refused:
    print(f"first refusal: {refused[0]}", flush=True)
print(f"container root files still present: {survived}", flush=True)

sys.exit(0 if survived and refused else 1)
