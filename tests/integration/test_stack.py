"""Against actual Compose services. Requires make up and exclusive use of the demo stack."""

import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from agentgate.cli import LOCAL_URL, demo_token
from agentgate.lab import Lab, body, reset_demo_quotas


def docker(*args, timeout=30):
    try:
        return subprocess.run(  # noqa: S603 - fixed local service operations
            ["docker", *args],  # noqa: S607
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        pytest.fail(f"Docker command failed: {args!r}\n{error.stdout}\n{error.stderr}")


def compose(*args, timeout=30):
    return docker("compose", *args, timeout=timeout)


def start_healthy(service, timeout=20):
    # Compose start --wait support/behavior varies; inspect only the restored service.
    compose("start", service)
    container_id = compose("ps", "--all", "--quiet", service).stdout.strip()
    assert container_id, f"No container found for {service}"
    deadline = time.monotonic() + timeout
    state = {}
    while (remaining := deadline - time.monotonic()) > 0:
        state = json.loads(
            docker(
                "inspect",
                "--format",
                "{{json .State}}",
                container_id,
                timeout=min(3, remaining),
            ).stdout
        )
        if state.get("Status") == "running" and state.get("Health", {}).get("Status") == "healthy":
            return
        if state.get("Status") in {"exited", "dead"}:
            break
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    logs = compose("logs", "--tail", "50", "--no-log-prefix", service, timeout=5)
    pytest.fail(
        f"{service} did not become healthy within {timeout}s. "
        f"State: {json.dumps(state)}\n{logs.stdout}\n{logs.stderr}"
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
        start_healthy("weather")


def test_network_and_key_isolation(client):
    config = json.loads(compose("config", "--format", "json").stdout)
    containers = json.loads(docker("inspect", *compose("ps", "--quiet").stdout.split()).stdout)
    services = {c["Config"]["Labels"]["com.docker.compose.service"]: c for c in containers}
    expected = {
        "gateway": {"edge", "control", "weather-net", "finance-net"},
        "opa": {"control"},
        "redis": {"control"},
        "weather": {"weather-net"},
        "finance": {"finance-net"},
    }
    names = {key: value["name"] for key, value in config["networks"].items()}
    assert set(services) == set(expected)
    for service, networks in expected.items():
        assert set(config["services"][service]["networks"]) == networks
        attached = services[service]["NetworkSettings"]["Networks"]
        print(
            f"{service} attachments: "
            + json.dumps(
                {
                    name: {"ip": n["IPAddress"], "aliases": n["Aliases"]}
                    for name, n in attached.items()
                }
            )
        )
        assert set(attached) == {names[name] for name in networks}
        mounts = services[service]["Mounts"]
        # Inspect every mount, not just the expected key paths in the container.
        assert not any(
            "private.pem" in m["Source"] or "private.pem" in m["Destination"] for m in mounts
        )
        if service in {"weather", "finance"}:
            assert not mounts, f"Unexpected workload mount: {service}: {mounts}"
    assert any(
        m["Destination"] == "/run/keys/public.pem" and not m["RW"]
        for m in services["gateway"]["Mounts"]
    )
    for network in json.loads(docker("network", "inspect", *names.values()).stdout):
        key = next(key for key, name in names.items() if name == network["Name"])
        members = {c["Id"] for service, c in services.items() if key in expected[service]}
        assert set(network["Containers"]) == members
        assert network["Internal"] == (key != "edge")
        print(f"{network['Name']}: internal={network['Internal']}, members={sorted(members)}")

    command = """
import json
import socket
import sys
from pathlib import Path
# Positive control: a broken container/network cannot make all negative probes pass.
with socket.create_connection(('gateway', 8080), timeout=2):
    print('gateway:8080 reachable', flush=True)
for host, port, numeric in json.loads(sys.argv[1]):
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                      flags=socket.AI_NUMERICHOST if numeric else 0)
    except socket.gaierror:
        if numeric:
            raise
        print(f'{host}:{port}: DNS unavailable; container IP is tested separately', flush=True)
        continue
    for family, kind, proto, _, address in addresses:
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(1)
            try:
                sock.connect(address)
            except OSError as error:
                print(f'{host}:{port} -> {address}: blocked ({error})', flush=True)
            else:
                raise SystemExit(f'ISOLATION FAILURE: connected to {host}:{port} at {address}')
for path in ('/run/keys/private.pem', '/app/.local/keys/private.pem'):
    assert not Path(path).exists(), f'Private key present: {path}'
    try:
        with open(path, 'rb'):
            raise AssertionError(f'Private key readable: {path}')
    except FileNotFoundError:
        pass
print('isolated; private keys absent and unreadable', flush=True)
"""
    for source, peer in (("weather", "finance"), ("finance", "weather")):
        targets = []
        for target, port in (("opa", 8181), ("redis", 6379), (peer, 8001)):
            assert services[target]["State"]["Health"]["Status"] == "healthy"
            targets.append((target, port, False))
            for network in services[target]["NetworkSettings"]["Networks"].values():
                assert network["IPAddress"], f"Missing IPv4 address for {target}"
                targets.append((network["IPAddress"], port, True))
                if network["GlobalIPv6Address"]:
                    targets.append((network["GlobalIPv6Address"], port, True))
        result = compose("exec", "-T", source, "python", "-c", command, json.dumps(targets))
        print(f"{source} probes:\n{result.stdout}")
        assert "isolated; private keys absent and unreadable" in result.stdout
