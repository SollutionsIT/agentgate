from typing import Any

import httpx

from agentgate.domain.decisions import GateError
from agentgate.telemetry.metrics import POLICY_SECONDS


class PolicyClient:
    def __init__(self, client: httpx.AsyncClient, origin: str) -> None:
        self.client = client
        self.origin = origin

    async def evaluate(self, data: dict[str, Any], rule: str = "allow") -> bool:
        try:
            with POLICY_SECONDS.time():
                response = await self.client.post(
                    f"{self.origin}/v1/data/agentgate/{rule}",
                    json={"input": data},
                )
                response.raise_for_status()
                result = response.json()
                if not isinstance(result, dict) or type(result.get("result")) is not bool:
                    raise ValueError("invalid policy result")
                return bool(result["result"])
        except (httpx.HTTPError, ValueError, TypeError) as error:
            raise GateError(503, "policy_unavailable") from error
