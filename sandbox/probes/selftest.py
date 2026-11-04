"""Report the boundary as seen from inside the container.

Prints the facts the command centre and the demo video quote. Exits 0 only if every
claim holds; any line containing the word breach means the boundary did not hold.
"""
import os
import sys

failures = []


def show(label, value):
    print(f"{label}: {value}", flush=True)


show("interpreter", sys.executable)
show("uid", os.getuid())
show("gid", os.getgid())
show("cwd", os.getcwd())

if os.path.isdir("/sys/class/net"):
    show("interfaces", sorted(os.listdir("/sys/class/net")))
else:
    show("interfaces", "/sys/class/net not visible")

cap_eff = None
for line in open("/proc/self/status", encoding="utf-8"):
    if line.startswith("CapEff:"):
        cap_eff = int(line.split()[1], 16)
    if line.startswith("NoNewPrivs:"):
        show("no_new_privileges", line.split()[1])
    if line.startswith("Seccomp:"):
        show("seccomp_mode", line.split()[1])

if cap_eff is None:
    failures.append("capabilities could not be read")
elif cap_eff != 0:
    failures.append(f"breach: container holds capabilities 0x{cap_eff:x}")
else:
    show("capabilities", "none (CapEff 0)")

for path, label in (("/probe/selftest.py", "/probe"), ("/etc/vulnigo-write-test", "/")):
    try:
        with open(path, "a"):
            failures.append(f"breach: {label} is writable")
    except PermissionError:
        show(label, "read-only or not permitted")
    except OSError:
        show(label, "not writable")

import socket

socket.setdefaulttimeout(3)
try:
    with socket.create_connection(("93.184.215.238", 80)):
        failures.append("breach: outbound network is available")
except OSError as exc:
    show("egress", f"no route ({exc.__class__.__name__})")

if failures:
    for f in failures:
        print(f, flush=True)
    sys.exit(1)

print("boundary verified from the inside", flush=True)
