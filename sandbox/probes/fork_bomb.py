"""Try to spawn more processes than pids-limit allows. Success means being refused."""
import errno
import os
import sys

want = int(sys.argv[1]) if len(sys.argv) > 1 else 500
spawned = 0
blocked = None

for _ in range(want):
    try:
        pid = os.fork()
    except OSError as exc:
        blocked = exc.errno
        break
    if pid == 0:
        os._exit(0)
    spawned += 1

print(f"requested {want} processes, spawned {spawned}", flush=True)

if blocked == errno.EAGAIN:
    print("blocked with EAGAIN -- pids.max reached", flush=True)
elif blocked is not None:
    print(f"blocked with errno {blocked}", flush=True)
else:
    print("spawned every requested process -- the limit did not hold", flush=True)

reaped = 0
while reaped < spawned:
    try:
        os.wait()
    except ChildProcessError:
        break
    reaped += 1

print(f"reaped {reaped} children", flush=True)
sys.exit(0 if blocked == errno.EAGAIN else 1)
