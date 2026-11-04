"""In-process pub/sub that feeds the Server-Sent Events stream."""
import asyncio
from collections import defaultdict


class Bus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, key: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs[key].add(q)
        return q

    def unsubscribe(self, key: str, q: asyncio.Queue) -> None:
        self._subs[key].discard(q)

    def publish(self, key: str, event: dict) -> None:
        for q in list(self._subs.get(key, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass


bus = Bus()
