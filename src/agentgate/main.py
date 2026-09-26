from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from agentgate.api.middleware import BodyLimit
from agentgate.api.routes import router
from agentgate.audit.logger import audit, configure_logging
from agentgate.auth.jwt import TokenVerifier
from agentgate.authorization.engine import AuthorizationEngine
from agentgate.config import Settings
from agentgate.domain.decisions import Decision, GateError
from agentgate.policy.client import PolicyClient
from agentgate.security.delegation import Delegations
from agentgate.security.rate_limit import RateLimiter
from agentgate.security.replay import ReplayGuard
from agentgate.services.gateway import Gateway


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        verifier = TokenVerifier(settings)
        redis = Redis.from_url(
            settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
        )
        async with httpx.AsyncClient(
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=50),
        ) as http:
            engine = AuthorizationEngine(PolicyClient(http, settings.opa_url), settings.environment)
            app.state.redis = redis
            app.state.gateway = Gateway(
                settings,
                verifier,
                engine,
                RateLimiter(redis, settings.rate_limit, settings.rate_window),
                ReplayGuard(redis),
                Delegations(redis, engine),
                http,
            )
            try:
                yield
            finally:
                await redis.aclose()

    app = FastAPI(
        title="Sollutions - AgentGate",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(BodyLimit)
    app.include_router(router)

    @app.exception_handler(GateError)
    async def gate_error(request: Request, error: GateError) -> JSONResponse:
        decision = error.decision
        headers = {"Cache-Control": "no-store"}
        if error.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if error.status == 429:
            headers["Retry-After"] = str(settings.rate_window)
        return JSONResponse(
            decision.model_dump(mode="json"), status_code=error.status, headers=headers
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
        audit("request_rejection", reason="invalid_request")
        # FastAPI's default validation details can echo attacker payloads and secrets.
        return JSONResponse(
            Decision(decision="deny", reason="invalid_request").model_dump(mode="json"),
            status_code=403,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception) -> JSONResponse:
        audit("internal_error", reason="service_unavailable")
        return JSONResponse({"decision": "deny", "reason": "service_unavailable"}, status_code=503)

    return app


app = create_app()
