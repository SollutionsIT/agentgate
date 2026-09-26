import json
import logging
import time
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError

from agentgate.audit.logger import audit
from agentgate.config import Settings
from agentgate.domain.decisions import Decision, GateError
from agentgate.domain.requests import AuthorizationRequest, DelegationRequest
from agentgate.security.delegation import Delegations, Grant
from agentgate.security.rate_limit import RateLimiter
from agentgate.security.replay import ReplayGuard


async def test_replay_atomic_key_and_expiry():
    redis = AsyncMock()
    redis.set.side_effect = [True, None]
    guard = ReplayGuard(redis)
    await guard.consume("finance-agent", "nonce", 300)
    with pytest.raises(GateError, match="replay_rejected"):
        await guard.consume("finance-agent", "nonce", 300)
    assert redis.set.call_args_list[0] == redis.set.call_args_list[1]
    assert redis.set.call_args.kwargs == {"nx": True, "ex": 300}


async def test_rate_limit_boundary():
    redis = AsyncMock()
    redis.eval.side_effect = [1, 2, 3]
    limiter = RateLimiter(redis, 2, 60)
    await limiter.check("travel-agent")
    await limiter.check("travel-agent")
    with pytest.raises(GateError) as error:
        await limiter.check("travel-agent")
    assert error.value.status == 429
    assert redis.eval.call_args.args[2:] == ("rate:travel-agent", 60)


async def test_storage_failure_fails_closed():
    redis = AsyncMock()
    redis.set.side_effect = RedisConnectionError()
    redis.eval.side_effect = RedisConnectionError()
    for operation in (
        ReplayGuard(redis).consume("agent", "nonce", 60),
        RateLimiter(redis, 2, 60).check("agent"),
    ):
        with pytest.raises(GateError) as error:
            await operation
        assert error.value.status == 503


@pytest.fixture
def delegation():
    redis, engine = AsyncMock(), AsyncMock()
    engine.environment = "development"
    engine.allowed.return_value = True
    engine.policy.evaluate.return_value = True
    grant = Grant(
        id=uuid4(),
        delegator="travel-agent",
        delegatee="planner-agent",
        action="weather.read",
        resource="weather-service",
        environment="development",
        expires_at=int(time.time()) + 60,
    )
    redis.get.return_value = grant.model_dump_json()
    request = AuthorizationRequest.model_validate(
        {
            "subject": {"agent_id": "planner-agent"},
            "action": "weather.read",
            "resource": "weather-service",
            "delegation_id": grant.id,
        }
    )
    return Delegations(redis, engine), grant, request


async def test_valid_delegation_rechecks_policy(delegation):
    service, grant, request = delegation
    assert await service.validate("planner-agent", request) == grant
    service.engine.allowed.assert_awaited_once()
    service.engine.policy.evaluate.assert_awaited_once()


@pytest.mark.parametrize(
    "change", ["expiry", "delegatee", "scope", "missing", "environment", "revoked"]
)
async def test_invalid_delegations(delegation, change):
    service, grant, request = delegation
    match change:
        case "expiry":
            grant.expires_at = 0
        case "delegatee":
            grant.delegatee = "admin-agent"
        case "scope":
            grant.action = "booking.search"
        case "environment":
            grant.environment = "production"
        case "revoked":
            service.engine.allowed.return_value = False
    service.redis.get.return_value = None if change == "missing" else grant.model_dump_json()
    with pytest.raises(GateError, match="invalid_delegation"):
        await service.validate("planner-agent", request)


@pytest.mark.parametrize("own,delegate", [(False, True), (True, False), (False, False)])
async def test_over_delegation(delegation, own, delegate):
    service, _, _ = delegation
    service.engine.allowed.return_value = own
    service.engine.policy.evaluate.return_value = delegate
    request = DelegationRequest(
        delegatee="planner-agent", action="finance.transfer.request", resource="finance-service"
    )
    with pytest.raises(GateError, match="delegation_not_allowed"):
        await service.create("travel-agent", int(time.time()) + 60, request)
    service.redis.set.assert_not_called()


async def test_grant_cannot_outlive_issuer_token(delegation, monkeypatch):
    service, _, _ = delegation
    monkeypatch.setattr("agentgate.security.delegation.time.time", lambda: 1000)
    grant = await service.create(
        "travel-agent",
        1020,
        DelegationRequest(
            delegatee="planner-agent",
            action="weather.read",
            resource="weather-service",
            ttl_seconds=300,
        ),
    )
    assert grant.expires_at == 1020
    assert service.redis.set.call_args.kwargs["ex"] == 20


def test_audit_allowlist_and_json_escaping(caplog):
    with caplog.at_level(logging.INFO, logger="agentgate.audit"):
        audit(
            "authorization_decision",
            reason="deny\nforged_event",
            authorization="Bearer secret",
            private_key="-----BEGIN PRIVATE KEY-----",
            payload={"secret": "hidden"},
        )
    assert "Bearer secret" not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
    assert "hidden" not in caplog.text
    parsed = json.loads(caplog.records[0].message)
    assert parsed["reason"] == "deny\nforged_event"
    assert len(caplog.records) == 1


@pytest.mark.parametrize(
    "values",
    [
        {"rate_limit": 0},
        {"replay_window": 0},
        {"weather_url": "file:///etc/passwd"},
        {"weather_url": "http://user:pass@weather"},
        {"weather_url": "http://weather/path"},
        {"redis_url": "http://redis"},
    ],
)
def test_config_validation(values):
    with pytest.raises(ValidationError):
        Settings(**values)


@pytest.mark.parametrize(
    "action", ["system", "../admin", "weather.read\n", "Weather.read", "a." + "a" * 100]
)
def test_capability_name_validation(action):
    with pytest.raises(ValidationError):
        AuthorizationRequest.model_validate(
            {
                "subject": {"agent_id": "travel-agent"},
                "action": action,
                "resource": "weather-service",
            }
        )


def test_decision_serialization():
    decision = Decision(decision="deny", reason="capability_not_allowed")
    assert Decision.model_validate_json(decision.model_dump_json()) == decision
    assert decision.timestamp.tzinfo is not None
