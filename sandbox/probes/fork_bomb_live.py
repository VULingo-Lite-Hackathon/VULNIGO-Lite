"""Like fork_bomb.py, but the children stay alive. gVisor does not count exited children against the pid limit,
so only live processes show whether the limit holds there. Success means being refused, or the sandbox being stopped."""
import errno
import os
import signal
import sys
import time

want = int(sys.argv[1]) if len(sys.argv) > 1 else 500
kids = []
blocked = None

for _ in range(want):
    try:
        pid = os.fork()
    except OSError as exc:
        blocked = exc.errno
        break
    if pid == 0:
        time.sleep(30)
        os._exit(0)
    kids.append(pid)

print(f"requested {want} processes, spawned {len(kids)}", flush=True)

if blocked == errno.EAGAIN:
    print("blocked with EAGAIN -- pids.max reached", flush=True)
elif blocked is not None:
    print(f"blocked with errno {blocked}", flush=True)
else:
    print("spawned every requested process -- the limit did not hold", flush=True)

for pid in kids:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
for _ in kids:
    try:
        os.wait()
    except ChildProcessError:
        break

sys.exit(0 if blocked == errno.EAGAIN else 1)
