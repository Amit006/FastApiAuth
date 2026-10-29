import json
import time
import redis as redis_lib


class RedisTokenStore:
    def __init__(self, client: redis_lib.Redis):
        self._r = client

    def save(self, token: str, user_id: str, absolute_exp: int) -> None:
        ttl = max(1, absolute_exp - int(time.time()))
        value = json.dumps({"user_id": user_id, "is_used": False})
        self._r.set(f"rt:{token}", value, ex=ttl)
        self._r.sadd(f"user_tokens:{user_id}", token)
        self._r.expireat(f"user_tokens:{user_id}", absolute_exp)

    def get(self, token: str) -> dict | None:
        raw = self._r.get(f"rt:{token}")
        if raw is None:
            return None
        return json.loads(raw)

    def mark_used(self, token: str) -> None:
        raw = self._r.get(f"rt:{token}")
        if raw is None:
            return
        data = json.loads(raw)
        data["is_used"] = True
        ttl = self._r.ttl(f"rt:{token}")
        self._r.set(f"rt:{token}", json.dumps(data), ex=max(1, ttl))

    def mark_used_if_unused(self, token: str) -> int:
        key = f"rt:{token}"
        with self._r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    if raw is None:
                        pipe.reset()
                        return 0
                    data = json.loads(raw)
                    if data["is_used"]:
                        pipe.reset()
                        return -1
                    data["is_used"] = True
                    ttl = pipe.ttl(key)
                    pipe.multi()
                    pipe.set(key, json.dumps(data), ex=max(1, ttl))
                    pipe.execute()
                    return 1
                except redis_lib.WatchError:
                    continue

    def revoke_all(self, user_id: str) -> None:
        tokens = self._r.smembers(f"user_tokens:{user_id}")
        for token in tokens:
            self._r.delete(f"rt:{token}")
        self._r.delete(f"user_tokens:{user_id}")
