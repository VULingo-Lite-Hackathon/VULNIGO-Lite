"""Allocate far past the container's memory cap. The cgroup should kill us."""
import sys

target_mb = int(sys.argv[1]) if len(sys.argv) > 1 else 4096
chunk = 16
held = []

for _ in range(target_mb // chunk):
    held.append(bytearray(chunk * 1024 * 1024))
    print(f"allocated {len(held) * chunk} MB", flush=True)

print("survived the whole allocation", flush=True)
sys.exit(1)
