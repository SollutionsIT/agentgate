from unittest.mock import AsyncMock

import httpx
import pytest

from agentgate.authorization.engine import AuthorizationEngine, policy_input
from agentgate.domain.decisions import GateError
from agentgate.domain.requests import AuthorizationRequest
from agentgate.policy.client import PolicyClient
from agentgate.policy.loader import POLICY, compare, evaluate


def request(**values):
    return AuthorizationRequest.model_validate(
        {
            "subject": {"agent_id": "travel-agent"},
            "action": "weather.read",
            "resource": "weather-service",
            **values,
        }
    )


def test_input_uses_verified_subject_and_server_context():
    data = policy_input("finance-agent", request(), "production")
    assert data == {
        "subject": {"agent_id": "finance-agent"},
        "action": "weather.read",
        "resource": "weather-service",
        "context": {"environment": "production"},
    }
    assert "request_id" not in data["context"]


@pytest.mark.parametrize(
    "values",
    [
        {"action": "secrets.read"},
        {"resource": "finance-service"},
        {"context": {"environment": "production"}},
    ],
)
async def test_deny_before_opa(values):
    policy = AsyncMock()
    assert not await AuthorizationEngine(policy, "development").allowed(
        "travel-agent", request(**values)
    )
    policy.evaluate.assert_not_called()


@pytest.mark.parametrize(
    "result",
    [{}, {"result": None}, {"result": "true"}, {"result": 1}, {"result": []}, {"result": {}}, []],
)
async def test_invalid_policy_response_fails_closed(result):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=result),
        )
    ) as client:
        with pytest.raises(GateError) as error:
            await PolicyClient(client, "http://opa").evaluate({})
    assert error.value.status == 503


@pytest.mark.parametrize("status", [403, 404, 500, 503])
async def test_policy_http_errors(status):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(status),
        )
    ) as client:
        with pytest.raises(GateError):
            await PolicyClient(client, "http://opa").evaluate({})


async def test_policy_transport_error():
    def unavailable(request):
        raise httpx.ConnectError("offline")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        with pytest.raises(GateError):
            await PolicyClient(client, "http://opa").evaluate({})


async def test_explicit_false_is_denial():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"result": False}),
        )
    ) as client:
        assert await PolicyClient(client, "http://opa").evaluate({}) is False


def test_real_rego_matrix():
    rows = evaluate(POLICY)
    allowed = {
        (r["input"]["subject"]["agent_id"], r["input"]["action"]) for r in rows if r["allow"]
    }
    assert ("travel-agent", "weather.read") in allowed
    assert ("travel-agent", "finance.transfer.request") not in allowed
    assert all(agent != "unknown-agent" for agent, _ in allowed)


def test_diff_detects_expansion_and_removal(tmp_path):
    changed = tmp_path / "changed.rego"
    changed.write_text(
        POLICY.read_text().replace(
            '"travel-agent": {"weather.read", "booking.search"}',
            '"travel-agent": {"weather.read", "finance.balance.read"}',
        )
    )
    diff = compare(POLICY, changed)
    assert any(
        row["action"] == "finance.balance.read" and row["control"] == "allow"
        for row in diff["newly_allowed"]
    )
    assert any(row["action"] == "booking.search" for row in diff["removed"])


def test_undefined_policy_diff_is_error(tmp_path):
    missing = tmp_path / "missing.rego"
    missing.write_text("package agentgate\nimport rego.v1\ndefault allow := false\n")
    with pytest.raises(RuntimeError):
        evaluate(missing)
