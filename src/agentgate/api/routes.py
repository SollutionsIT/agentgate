from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis.exceptions import RedisError

from agentgate.api.dependencies import Caller, Service
from agentgate.domain.decisions import Decision, GateError
from agentgate.domain.requests import AuthorizationRequest, DelegationRequest
from agentgate.security.delegation import Grant

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request, service: Service) -> dict[str, str]:
    try:
        await request.app.state.redis.ping()
        # Verify the expected policy is loaded, not merely that OPA's process is alive.
        if not await service.engine.policy.evaluate({}, "ready"):
            raise GateError(503, "dependency_unavailable")
    except (RedisError, GateError) as error:
        raise GateError(503, "dependency_unavailable") from error
    return {"status": "ready"}


@router.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})


@router.post("/v1/authorize")
async def authorize(body: AuthorizationRequest, caller: Caller, service: Service) -> Decision:
    return await service.authorize(caller, body)


@router.post("/v1/delegations", status_code=201)
async def delegate(body: DelegationRequest, caller: Caller, service: Service) -> Grant:
    return await service.delegate(caller, body)


@router.post("/v1/proxy/{target}")
async def proxy(
    target: str, body: AuthorizationRequest, caller: Caller, service: Service
) -> Response:
    content = await service.proxy(caller, target, body)
    return Response(content, media_type="application/json")
