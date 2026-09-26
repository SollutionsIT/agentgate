import time
from uuid import UUID, uuid4

from pydantic import Field, ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError

from agentgate.authorization.engine import AuthorizationEngine, policy_input
from agentgate.domain.decisions import GateError
from agentgate.domain.requests import (
    AgentID,
    AuthorizationRequest,
    CapabilityName,
    Context,
    DelegationRequest,
    ResourceName,
    StrictModel,
    Subject,
)


class Grant(StrictModel):
    id: UUID
    delegator: AgentID
    delegatee: AgentID
    action: CapabilityName
    resource: ResourceName
    environment: str
    expires_at: int = Field(strict=True)


class Delegations:
    def __init__(self, redis: Redis, engine: AuthorizationEngine) -> None:
        self.redis = redis
        self.engine = engine

    async def can_delegate(
        self,
        delegator: str,
        delegatee: str,
        request: AuthorizationRequest,
    ) -> bool:
        if not await self.engine.allowed(delegator, request):
            return False
        data = policy_input(delegator, request, self.engine.environment)
        data["delegatee"] = delegatee
        return await self.engine.policy.evaluate(data, "can_delegate")

    async def create(self, agent: str, token_expiry: int, request: DelegationRequest) -> Grant:
        authorization = AuthorizationRequest(
            subject=Subject(agent_id=agent),
            action=request.action,
            resource=request.resource,
            context=request.context,
        )
        if not await self.can_delegate(agent, request.delegatee, authorization):
            raise GateError(403, "delegation_not_allowed")
        now = int(time.time())
        ttl = min(request.ttl_seconds, token_expiry - now)
        if ttl <= 0:
            raise GateError(403, "delegation_not_allowed")
        grant = Grant(
            id=uuid4(),
            delegator=agent,
            delegatee=request.delegatee,
            action=request.action,
            resource=request.resource,
            environment=self.engine.environment,
            expires_at=now + ttl,
        )
        try:
            await self.redis.set(f"delegation:{grant.id}", grant.model_dump_json(), ex=ttl)
        except RedisError as error:
            raise GateError(503, "security_storage_unavailable") from error
        return grant

    async def validate(self, agent: str, request: AuthorizationRequest) -> Grant:
        try:
            raw = await self.redis.get(f"delegation:{request.delegation_id}")
            if not raw:
                raise GateError(403, "invalid_delegation")
            grant = Grant.model_validate_json(raw)
        except RedisError as error:
            raise GateError(503, "security_storage_unavailable") from error
        except ValidationError as error:
            raise GateError(403, "invalid_delegation") from error
        if (
            grant.id != request.delegation_id
            or grant.delegatee != agent
            or grant.action != request.action
            or grant.resource != request.resource
            or grant.environment != self.engine.environment
            or request.context.environment != self.engine.environment
            or grant.expires_at <= int(time.time())
        ):
            raise GateError(403, "invalid_delegation")
        # Re-evaluate the delegator's CURRENT privileges and delegation rules.
        # A grant is not a policy snapshot and cannot be chained/redelegated.
        original = AuthorizationRequest(
            subject=Subject(agent_id=grant.delegator),
            action=grant.action,
            resource=grant.resource,
            context=Context(environment=request.context.environment),
        )
        if not await self.can_delegate(grant.delegator, agent, original):
            raise GateError(403, "invalid_delegation")
        return grant
