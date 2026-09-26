from redis.asyncio import Redis
from redis.exceptions import RedisError

from agentgate.domain.decisions import GateError

# INCR and expiry are one atomic operation; concurrent workers cannot lose expiry.
SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"""


class RateLimiter:
    def __init__(self, redis: Redis, limit: int, window: int) -> None:
        self.redis = redis
        self.limit = limit
        self.window = window

    async def check(self, agent: str) -> None:
        try:
            count = await self.redis.eval(SCRIPT, 1, f"rate:{agent}", self.window)
        except RedisError as error:
            raise GateError(503, "security_storage_unavailable") from error
        if int(count) > self.limit:
            raise GateError(429, "rate_limit_exceeded")
