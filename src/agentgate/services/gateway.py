import asyncio
import time
from dataclasses import dataclass
from uuid import uuid4

import httpx

from agentgate.audit.logger import audit
from agentgate.auth.identity import Identity
from agentgate.auth.jwt import TokenVerifier
from agentgate.authorization.engine import AuthorizationEngine
from agentgate.authorization.models import CAPABILITIES
from agentgate.config import Settings
from agentgate.domain.decisions import Decision, GateError
from agentgate.domain.requests import AuthorizationRequest, DelegationRequest
from agentgate.security.delegation import Delegations, Grant
from agentgate.security.rate_limit import RateLimiter
from agentgate.security.replay import ReplayGuard
from agentgate.telemetry.metrics import (
    AUTH_FAILURES,
    DECISIONS,
    PROXY,
    RATE_REJECTIONS,
    REPLAYS,
    REQUESTS,
)


@dataclass(frozen=True)
class Target:
    action: str
    resource: str
    method: str
    url: str


class Gateway:
    def __init__(
        self,
        settings: Settings,
        verifier: TokenVerifier,
        engine: AuthorizationEngine,
        limiter: RateLimiter,
        replay: ReplayGuard,
        delegations: Delegations,
        http: httpx.AsyncClient,
    ) -> None:
        self.settings = settings
        self.verifier = verifier
        self.engine = engine
        self.limiter = limiter
        self.replay = replay
        self.delegations = delegations
        self.http = http
        self.targets = {
            "weather": Target(
                "weather.read", "weather-service", "GET", f"{settings.weather_url}/weather"
            ),
            "balance": Target(
                "finance.balance.read", "finance-service", "GET", f"{settings.finance_url}/balance"
            ),
            "transfer-preview": Target(
                "finance.transfer.request",
                "finance-service",
                "POST",
                f"{settings.finance_url}/transfer-preview",
            ),
        }

    async def authenticate(self, authorization: str | None) -> Identity:
        REQUESTS.inc()
        try:
            if not authorization or not authorization.startswith("Bearer "):
                raise GateError(401, "authentication_failed")
            identity = self.verifier.verify(authorization[7:])
        except GateError as error:
            AUTH_FAILURES.inc()
            audit(
                "authentication_failure",
                reason="authentication_failed",
                request_id=uuid4(),
                decision_id=error.decision.decision_id,
            )
            raise
        try:
            await self.limiter.check(identity.sub)
        except GateError as error:
            self.rejection(error, identity.sub)
            raise
        return identity

    def rejection(self, error: GateError, agent: str, **fields: object) -> None:
        event = "authorization_deny"
        if error.status == 429:
            RATE_REJECTIONS.inc()
            event = "rate_limit_rejection"
        elif error.reason == "replay_rejected":
            REPLAYS.inc()
            event = "replay_rejection"
        elif error.reason == "policy_unavailable":
            event = "policy_error"
        fields.setdefault("request_id", uuid4())
        fields.setdefault("decision_id", error.decision.decision_id)
        audit(event, agent_id=agent, decision="deny", reason=error.reason, **fields)

    async def consume(self, identity: Identity, nonce: object) -> None:
        if nonce is None:
            raise GateError(403, "nonce_required")
        # Keep the nonce for at least the full remaining lifetime of this credential.
        ttl = max(self.settings.replay_window, identity.exp - int(time.time()))
        await self.replay.consume(identity.sub, str(nonce), ttl)

    async def authorize(self, identity: Identity, request: AuthorizationRequest) -> Decision:
        fields = {
            "request_id": str(request.context.request_id),
            "action": request.action,
            "resource": request.resource,
        }
        try:
            if request.subject.agent_id != identity.sub:
                raise GateError(403, "subject_mismatch")
            if request.delegation_id:
                grant = await self.delegations.validate(identity.sub, request)
                audit("delegation_use", agent_id=identity.sub, delegation_id=grant.id, **fields)
                allowed = True
            else:
                allowed = await self.engine.allowed(identity.sub, request)
            if not allowed:
                raise GateError(403, "capability_not_allowed")
            if CAPABILITIES[request.action].sensitive:
                await self.consume(identity, request.context.nonce)
            decision = Decision(decision="allow", reason="authorized")
        except GateError as error:
            decision = error.decision
            DECISIONS.labels("deny").inc()
            self.rejection(error, identity.sub, decision_id=decision.decision_id, **fields)
            # Keep the same decision ID in the response and audit.
            error.decision = decision
            raise
        except Exception as error:
            # Unexpected authorization failures MUST NOT result in a forwarding attempt.
            failure = GateError(503, "authorization_unavailable")
            DECISIONS.labels("deny").inc()
            self.rejection(failure, identity.sub, **fields)
            raise failure from error
        DECISIONS.labels("allow").inc()
        audit("authorization_decision", agent_id=identity.sub, **decision.model_dump(), **fields)
        return decision

    async def delegate(self, identity: Identity, request: DelegationRequest) -> Grant:
        try:
            # Creating a grant is itself a sensitive operation.
            await self.consume(identity, request.context.nonce)
            grant = await self.delegations.create(identity.sub, identity.exp, request)
        except GateError as error:
            self.rejection(error, identity.sub, request_id=request.context.request_id)
            audit(
                "delegation_rejection",
                agent_id=identity.sub,
                reason=error.reason,
                action=request.action,
                resource=request.resource,
            )
            raise
        audit(
            "delegation_creation",
            agent_id=identity.sub,
            delegation_id=grant.id,
            delegatee=grant.delegatee,
            action=grant.action,
            resource=grant.resource,
            request_id=request.context.request_id,
        )
        return grant

    async def proxy(
        self, identity: Identity, target_name: str, request: AuthorizationRequest
    ) -> bytes:
        target = self.targets.get(target_name)
        if target is None or (target.action, target.resource) != (request.action, request.resource):
            error = GateError(403, "target_not_allowed")
            self.rejection(error, identity.sub, request_id=request.context.request_id)
            raise error
        await self.authorize(identity, request)
        try:
            # No caller URL, path, method, headers, query, cookies or payload is forwarded.
            # Suppress the shared client's cookie jar: downstream sessions cannot cross identities.
            async with (
                asyncio.timeout(5),
                self.http.stream(
                    target.method,
                    target.url,
                    headers={"Cookie": ""},
                ) as response,
            ):
                if response.status_code != 200:
                    raise GateError(502, "downstream_unavailable")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 65536:
                        raise GateError(502, "downstream_unavailable")
            PROXY.labels("success").inc()
            return bytes(body)
        except (httpx.HTTPError, GateError, TimeoutError) as error:
            PROXY.labels("failure").inc()
            audit(
                "proxy_failure",
                agent_id=identity.sub,
                reason="downstream_unavailable",
                request_id=request.context.request_id,
            )
            raise GateError(502, "downstream_unavailable") from error
