"""Try to reach the cloud metadata address, the internet, and DNS. All must fail."""
import socket
import sys

socket.setdefaulttimeout(3)

# 169.254.169.254 is the link-local address every cloud provider serves instance
# metadata and attached credentials from. Reaching it is how a sandboxed job turns
# into an account takeover.
targets = [
    ("link-local metadata", "169.254.169.254", 80),
    ("public internet", "93.184.215.238", 80),
]

expected = len(targets) + 1
unreachable = 0

for label, host, port in targets:
    try:
        with socket.create_connection((host, port)):
            print(f"{label}: REACHABLE", flush=True)
    except OSError as exc:
        unreachable += 1
        print(f"{label}: no route ({exc.__class__.__name__})", flush=True)

try:
    socket.getaddrinfo("example.com", 80)
    print("dns: RESOLVED", flush=True)
except OSError as exc:
    unreachable += 1
    print(f"dns: no resolution ({exc.__class__.__name__})", flush=True)

sys.exit(0 if unreachable == expected else 1)
