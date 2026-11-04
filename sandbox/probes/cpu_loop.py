"""Burn CPU forever. Only the wall-clock timeout should stop this."""
import time

started = time.time()
while True:
    _ = sum(range(20000))
    if time.time() - started > 600:
        break

print("survived 600 seconds of spinning", flush=True)
