import hashlib

from redis.asyncio import Redis
from redis.exceptions import RedisError

from agentgate.domain.decisions import GateError


class ReplayGuard:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def consume(self, agent: str, nonce: str, ttl: int) -> None:
        # Identity scoped: changing an access token must not reset nonce history.
        key = hashlib.sha256(f"{agent}:{nonce}".encode()).hexdigest()
        try:
            inserted = await self.redis.set(f"replay:{key}", "1", nx=True, ex=ttl)
        except RedisError as error:
            raise GateError(503, "security_storage_unavailable") from error
        if not inserted:
            raise GateError(403, "replay_rejected")
