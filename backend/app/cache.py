"""Redis-backed latest-state cache + event channel; transparently falls back to memory."""
import json
import logging

from .config import settings

log = logging.getLogger("sentineledge.cache")


class Cache:
    def __init__(self):
        self.mem: dict[str, str] = {}
        self.r = None
        if settings.redis_url:
            try:
                import redis
                self.r = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
                self.r.ping()
            except Exception as e:  # pragma: no cover
                log.warning("redis unavailable (%s) - using in-memory cache", e)
                self.r = None

    def set_devices(self, states: dict) -> None:
        mapping = {k: json.dumps(v) for k, v in states.items()}
        if not mapping:
            return
        try:
            if self.r:
                self.r.hset("se:fleet", mapping=mapping)
                return
        except Exception:  # pragma: no cover
            pass
        self.mem.update(mapping)

    def fleet(self) -> dict:
        try:
            if self.r:
                return {k: json.loads(v) for k, v in self.r.hgetall("se:fleet").items()}
        except Exception:  # pragma: no cover
            pass
        return {k: json.loads(v) for k, v in self.mem.items()}

    def publish(self, channel: str, msg: dict) -> None:
        try:
            if self.r:
                self.r.publish(f"se:{channel}", json.dumps(msg))
        except Exception:  # pragma: no cover
            pass

    def clear(self):
        self.mem.clear()
        if self.r:  # pragma: no cover
            self.r.delete("se:fleet")


cache = Cache()
