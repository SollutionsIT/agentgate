from typing import Any

from agentgate.authorization.models import CAPABILITIES
from agentgate.domain.requests import AuthorizationRequest
from agentgate.policy.client import PolicyClient


def policy_input(agent: str, request: AuthorizationRequest, environment: str) -> dict[str, Any]:
    return {
        "subject": {"agent_id": agent},
        "action": request.action,
        "resource": request.resource,
        "context": {"environment": environment},
    }


class AuthorizationEngine:
    def __init__(self, policy: PolicyClient, environment: str) -> None:
        self.policy = policy
        self.environment = environment

    async def allowed(self, agent: str, request: AuthorizationRequest) -> bool:
        capability = CAPABILITIES.get(request.action)
        if (
            capability is None
            or capability.resource != request.resource
            or request.context.environment != self.environment
        ):
            return False
        return await self.policy.evaluate(policy_input(agent, request, self.environment))
