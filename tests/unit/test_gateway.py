import logging
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from agentgate.auth.identity import Identity
from agentgate.auth.jwt import TokenVerifier
from agentgate.authorization.engine import AuthorizationEngine
from agentgate.domain.decisions import GateError
from agentgate.domain.requests import AuthorizationRequest
from agentgate.main import create_app
from agentgate.security.delegation import Delegations
from agentgate.security.rate_limit import RateLimiter
from agentgate.security.replay import ReplayGuard
from agentgate.services.gateway import Gateway


@pytest.fixture
def api(settings):
    app = create_app(settings)
    policy, redis = AsyncMock(), AsyncMock()
    policy.evaluate.return_value = True
    redis.eval.return_value = 1
    redis.set.return_value = True
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"demo": True}))
    )
    engine = AuthorizationEngine(policy, "development")
    service = Gateway(
        settings,
        TokenVerifier(settings),
        engine,
        RateLimiter(redis, 30, 60),
        ReplayGuard(redis),
        Delegations(redis, engine),
        http,
    )
    with TestClient(app) as client:
        app.state.gateway = service
        yield client, service


def payload(**overrides):
    return {
        "subject": {"agent_id": "travel-agent"},
        "action": "weather.read",
        "resource": "weather-service",
        **overrides,
    }


def test_api_allow_and_deny(api, token):
    client, service = api
    headers = {"Authorization": f"Bearer {token()}"}
    assert client.post("/v1/authorize", headers=headers, json=payload()).status_code == 200
    service.engine.policy.evaluate.return_value = False
    response = client.post("/v1/authorize", headers=headers, json=payload())
    assert response.status_code == 403
    assert response.json()["reason"] == "capability_not_allowed"


def test_subject_cannot_be_asserted(api, token):
    client, service = api
    response = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token()}"},
        json=payload(subject={"agent_id": "admin-agent"}),
    )
    assert response.status_code == 403
    assert response.json()["reason"] == "subject_mismatch"
    service.engine.policy.evaluate.assert_not_called()


def test_auth_header_and_keys_never_logged(api, token, caplog, keys):
    client, _ = api
    logger = logging.getLogger("agentgate.audit")
    logger.addHandler(caplog.handler)
    raw = token()
    headers = {"Authorization": f"Bearer {raw}"}
    response = client.post("/v1/authorize", headers=headers, json=payload())
    client.post("/v1/authorize", headers={"Authorization": "Bearer invalid_secret"}, json=payload())
    client.post("/v1/authorize", headers=headers, json=payload(extra={"private_key": "SECRET"}))
    assert response.status_code == 200
    assert response.json()["decision_id"] in caplog.text
    assert "authorization_decision" in caplog.text
    assert "authentication_failure" in caplog.text
    assert raw not in caplog.text
    assert "Bearer" not in caplog.text
    assert "invalid_secret" not in caplog.text
    assert "SECRET" not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
    logger.removeHandler(caplog.handler)


@pytest.mark.parametrize(
    "error", [GateError(503, "policy_unavailable"), RuntimeError("secret details")]
)
def test_fail_closed_authorization_exception(api, token, error):
    client, service = api
    service.engine.policy.evaluate.side_effect = error
    response = client.post(
        "/v1/proxy/weather", headers={"Authorization": f"Bearer {token()}"}, json=payload()
    )
    assert response.status_code == 503
    assert "secret details" not in response.text


@pytest.mark.parametrize(
    "target,values",
    [
        ("unregistered", {}),
        ("weather", {"url": "http://169.254.169.254"}),
        ("weather", {"resource": "finance-service"}),
        ("balance", {}),
        ("weather", {"action": "booking.search"}),
    ],
)
def test_closed_proxy_registry(api, token, target, values):
    client, _ = api
    response = client.post(
        f"/v1/proxy/{target}",
        headers={"Authorization": f"Bearer {token()}"},
        json=payload(**values),
    )
    assert response.status_code == 403


def test_request_body_limit(api):
    client, _ = api
    assert client.post("/v1/authorize", content="a" * 16385).status_code == 413


@pytest.mark.parametrize("nonce,expected", [(None, 403), (str(uuid4()), 200)])
def test_sensitive_nonce_required(api, token, nonce, expected):
    client, _ = api
    response = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token()}"},
        json=payload(action="booking.create", resource="booking-service", context={"nonce": nonce}),
    )
    assert response.status_code == expected


async def test_proxy_does_not_forward_credentials_or_follow_redirects(settings, token):
    seen = []

    def redirect(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    policy, redis = AsyncMock(), AsyncMock()
    policy.evaluate.return_value = True
    engine = AuthorizationEngine(policy, "development")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(redirect), follow_redirects=False
    ) as http:
        service = Gateway(
            settings,
            TokenVerifier(settings),
            engine,
            RateLimiter(redis, 30, 60),
            ReplayGuard(redis),
            Delegations(redis, engine),
            http,
        )
        identity = service.verifier.verify(token())
        with pytest.raises(GateError, match="downstream_unavailable"):
            await service.proxy(identity, "weather", AuthorizationRequest.model_validate(payload()))
    assert len(seen) == 1
    assert str(seen[0].url) == "http://weather:8001/weather"
    assert "authorization" not in seen[0].headers


async def test_replay_ttl_covers_token_lifetime(settings):
    replay = AsyncMock()
    service = Gateway(
        settings, AsyncMock(), AsyncMock(), AsyncMock(), replay, AsyncMock(), AsyncMock()
    )
    import time

    identity = Identity(
        sub="finance-agent", jti="a" * 32, iat=int(time.time()), exp=int(time.time()) + 900
    )
    await service.consume(identity, uuid4())
    assert replay.consume.call_args.args[2] >= 899


async def test_downstream_cookie_cannot_cross_identities(settings, token):
    seen = []

    def response(request):
        seen.append(request)
        return httpx.Response(
            200, json={"demo": True}, headers={"Set-Cookie": "session=privileged"}
        )

    policy, redis = AsyncMock(), AsyncMock()
    policy.evaluate.return_value = True
    engine = AuthorizationEngine(policy, "development")
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as http:
        service = Gateway(
            settings,
            TokenVerifier(settings),
            engine,
            RateLimiter(redis, 30, 60),
            ReplayGuard(redis),
            Delegations(redis, engine),
            http,
        )
        for agent in ("admin-agent", "travel-agent"):
            identity = service.verifier.verify(token(sub=agent))
            await service.proxy(
                identity,
                "weather",
                AuthorizationRequest.model_validate(payload(subject={"agent_id": agent})),
            )
    assert len(seen) == 2
    assert all(not request.headers.get("cookie") for request in seen)


async def test_downstream_oversized_response_rejected(settings, token):
    policy, redis = AsyncMock(), AsyncMock()
    policy.evaluate.return_value = True
    engine = AuthorizationEngine(policy, "development")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"a" * 65537))
    ) as http:
        service = Gateway(
            settings,
            TokenVerifier(settings),
            engine,
            RateLimiter(redis, 30, 60),
            ReplayGuard(redis),
            Delegations(redis, engine),
            http,
        )
        with pytest.raises(GateError, match="downstream_unavailable"):
            await service.proxy(
                service.verifier.verify(token()),
                "weather",
                AuthorizationRequest.model_validate(payload()),
            )
