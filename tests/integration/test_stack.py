"""Against actual Compose services. Requires make up and exclusive use of the demo stack."""

import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from agentgate.cli import LOCAL_URL, demo_token
from agentgate.lab import Lab, body, reset_demo_quotas


def compose(*args):
    return subprocess.run(  # noqa: S603 - fixed local service operations
        ["docker", "compose", *args],  # noqa: S607
        check=True,
        text=True,  # noqa: S603,S607
        capture_output=True,
        timeout=30,
    )


@pytest.fixture
def client():
    with httpx.Client(base_url=LOCAL_URL, timeout=8, trust_env=False) as client:
        assert client.get("/ready").status_code == 200, "Run make up first"
        reset_demo_quotas()
        yield client
        reset_demo_quotas()


def wait_ready(client):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if client.get("/ready").status_code == 200:
            return
        time.sleep(0.1)
    pytest.fail("Dependencies did not recover")


def test_security_lab_and_audit(client):
    lab = Lab(client)
    outcomes = lab.run()
    assert len(outcomes) == 25
    assert all(result.passed for result in outcomes), outcomes
    logs = compose("logs", "--no-log-prefix", "gateway").stdout
    for token in lab.tokens:
        assert token not in logs
    assert "Authorization: Bearer" not in logs
    assert "BEGIN PRIVATE KEY" not in logs
    events = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    names = {event["event"] for event in events}
    assert {
        "authorization_decision",
        "authentication_failure",
        "replay_rejection",
        "rate_limit_rejection",
        "delegation_creation",
        "delegation_use",
        "delegation_rejection",
    } <= names


def test_metrics_increment(client):
    def counter(name):
        lines = client.get("/metrics").text.splitlines()
        return float(next(line.split()[-1] for line in lines if line.startswith(name + " ")))

    before = counter('agentgate_authorization_decisions_total{decision="allow"}')
    result = client.post(
        "/v1/authorize",
        json=body(),
        headers={"Authorization": f"Bearer {demo_token('travel-agent')}"},
    )
    assert result.status_code == 200
    assert counter('agentgate_authorization_decisions_total{decision="allow"}') == before + 1


def test_opa_outage_fails_closed(client):
    compose("stop", "opa")
    try:
        result = client.post(
            "/v1/proxy/weather",
            json=body(),
            headers={"Authorization": f"Bearer {demo_token('travel-agent')}"},
        )
        assert result.status_code == 503
        assert result.json()["reason"] == "policy_unavailable"
        assert client.get("/ready").status_code == 503
    finally:
        compose("start", "opa")
        wait_ready(client)


def test_redis_outage_and_replay_persistence(client):
    token = demo_token("finance-agent")
    headers = {"Authorization": f"Bearer {token}"}
    payload = body("finance-agent", "finance.transfer.request", "finance-service")
    assert client.post("/v1/authorize", headers=headers, json=payload).status_code == 200
    compose("stop", "redis")
    try:
        result = client.post("/v1/authorize", headers=headers, json=payload)
        assert result.status_code == 503
        assert result.json()["reason"] == "security_storage_unavailable"
    finally:
        compose("start", "redis")
        wait_ready(client)
    result = client.post("/v1/authorize", headers=headers, json=payload)
    assert result.status_code == 403
    assert result.json()["reason"] == "replay_rejected"


def test_replay_race_only_one_succeeds(client):
    token = demo_token("finance-agent")
    payload = body("finance-agent", "finance.transfer.request", "finance-service")

    def attempt(_):
        return client.post(
            "/v1/authorize", json=payload, headers={"Authorization": f"Bearer {token}"}
        ).status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(attempt, range(20)))
    assert statuses.count(200) == 1
    assert statuses.count(403) == 19
    # Reissuing a JWT for the same agent cannot reset nonce history.
    response = client.post(
        "/v1/authorize",
        json=payload,
        headers={"Authorization": f"Bearer {demo_token('finance-agent')}"},
    )
    assert response.json()["reason"] == "replay_rejected"


def test_rate_race_and_token_rotation(client):
    headers = {"Authorization": f"Bearer {demo_token('weather-agent')}"}
    payload = body("weather-agent", "system.health.read", "system-service")

    def attempt(_):
        return client.post("/v1/authorize", json=payload, headers=headers).status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(attempt, range(40)))
    assert statuses.count(200) == 30
    assert statuses.count(429) == 10
    headers = {"Authorization": f"Bearer {demo_token('weather-agent')}"}
    assert client.post("/v1/authorize", json=payload, headers=headers).status_code == 429


def test_downstream_failure(client):
    compose("stop", "weather")
    try:
        result = client.post(
            "/v1/proxy/weather",
            json=body(),
            headers={"Authorization": f"Bearer {demo_token('travel-agent')}"},
        )
        assert result.status_code == 502
        assert result.json()["reason"] == "downstream_unavailable"
    finally:
        compose("start", "--wait", "--wait-timeout", "20", "weather")


def test_network_and_key_isolation(client):
    # A protected workload must not resolve the control plane or its peer workload.
    command = """
import socket
from pathlib import Path
for host in ('opa', 'redis', 'finance'):
    try:
        socket.getaddrinfo(host, 80)
    except socket.gaierror:
        continue
    raise SystemExit('unexpected cross-network service resolution')
assert not Path('/run/keys/private.pem').exists()
assert not Path('/app/.local/keys/private.pem').exists()
print('isolated')
"""
    assert "isolated" in compose("exec", "-T", "weather", "python", "-c", command).stdout
    inspect = subprocess.run(  # noqa: S603
        [  # noqa: S607 - fixed local inspection
            "docker",
            "inspect",
            "agentgate-gateway-1",
            "--format",  # noqa: S607
            "{{json .HostConfig.Binds}}",
        ],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    assert "private.pem" not in inspect
    assert "public.pem" in inspect
