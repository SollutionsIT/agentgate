"""Bounded, deterministic local security checks. No configurable destinations or scanning."""

import json
import subprocess
import time
from dataclasses import asdict, dataclass
from uuid import uuid4

import httpx
import jwt
import typer
from cryptography.hazmat.primitives.asymmetric import rsa

from agentgate.cli import LOCAL_URL, demo_token
from agentgate.policy.loader import AGENTS

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    help="Safe verification against the fixed loopback Compose demo only.",
)


@dataclass
class Outcome:
    scenario: str
    expected_status: int
    actual_status: int
    passed: bool


def reset_demo_quotas() -> None:
    # Operator-side test setup, never exposed through a gateway API.
    subprocess.run(  # noqa: S603
        [  # noqa: S607 - fixed local Compose command
            "docker",
            "compose",
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "DEL",  # noqa: S607
            *[f"rate:{agent}" for agent in [*AGENTS, "unknown-agent"]],
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )


def body(
    agent: str = "travel-agent",
    action: str = "weather.read",
    resource: str = "weather-service",
    **extra: object,
) -> dict[str, object]:
    return {
        "subject": {"agent_id": agent},
        "action": action,
        "resource": resource,
        "context": {"nonce": str(uuid4())},
        **extra,
    }


class Lab:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        self.outcomes: list[Outcome] = []
        self.tokens: list[str] = []

    def check(
        self,
        name: str,
        token: str | None,
        payload: dict[str, object],
        status: int,
        reason: str | None = None,
        path: str = "/v1/authorize",
    ) -> httpx.Response:
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        if token:
            self.tokens.append(token)
        response = self.client.post(path, json=payload, headers=headers)
        matched = response.status_code == status
        if reason is not None:
            matched = matched and response.json().get("reason") == reason
        self.outcomes.append(Outcome(name, status, response.status_code, matched))
        return response

    def run(self) -> list[Outcome]:
        reset_demo_quotas()
        travel = demo_token("travel-agent")
        finance = demo_token("finance-agent")
        planner = demo_token("planner-agent")
        now = int(time.time())
        self.check(
            "Unknown agent",
            demo_token("unknown-agent"),
            body("unknown-agent"),
            403,
            "capability_not_allowed",
        )
        self.check(
            "Expired JWT",
            demo_token("travel-agent", iat=now - 120, nbf=now - 120, exp=now - 60),
            body(),
            401,
            "authentication_failed",
        )
        self.check(
            "Wrong audience",
            demo_token("travel-agent", aud="other"),
            body(),
            401,
            "authentication_failed",
        )
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = jwt.decode(travel, options={"verify_signature": False})
        self.check(
            "Wrong signing key",
            jwt.encode(claims, wrong_key, algorithm="RS256"),
            body(),
            401,
            "authentication_failed",
        )
        parts = travel.split(".")
        parts[1] = parts[1][:-5] + "AAAAA"
        self.check("Tampered JWT", ".".join(parts), body(), 401, "authentication_failed")
        self.check(
            "Forbidden capability",
            travel,
            body(action="finance.transfer.request", resource="finance-service"),
            403,
            "capability_not_allowed",
        )
        self.check(
            "Unknown capability", travel, body(action="secrets.read"), 403, "capability_not_allowed"
        )
        self.check(
            "Subject impersonation",
            travel,
            body("admin-agent", "system.admin", "system-service"),
            403,
            "subject_mismatch",
        )
        delegation = {
            "delegatee": "planner-agent",
            "action": "weather.read",
            "resource": "weather-service",
            "context": {"nonce": str(uuid4())},
            "ttl_seconds": 60,
        }
        self.check(
            "Over-delegation",
            travel,
            {**delegation, "action": "finance.transfer.request", "resource": "finance-service"},
            403,
            "delegation_not_allowed",
            "/v1/delegations",
        )
        grant = self.check(
            "Explicit delegation creation",
            travel,
            {**delegation, "context": {"nonce": str(uuid4())}},
            201,
            path="/v1/delegations",
        )
        if grant.status_code != 201:
            return self.outcomes
        grant_id = grant.json()["id"]
        self.check(
            "Valid scoped delegation",
            planner,
            body("planner-agent", delegation_id=grant_id),
            200,
            "authorized",
        )
        self.check(
            "Delegation scope escalation",
            planner,
            body("planner-agent", "system.admin", "system-service", delegation_id=grant_id),
            403,
            "invalid_delegation",
        )
        short_grant = self.check(
            "Time-bounded grant creation",
            travel,
            {**delegation, "ttl_seconds": 1, "context": {"nonce": str(uuid4())}},
            201,
            path="/v1/delegations",
        )
        if short_grant.status_code != 201:
            return self.outcomes
        # Wait to the returned absolute expiry, not an assumed processing duration.
        delay = max(0.0, short_grant.json()["expires_at"] - time.time()) + 0.1
        time.sleep(min(delay, 2))
        self.check(
            "Expired delegation",
            planner,
            body("planner-agent", delegation_id=short_grant.json()["id"]),
            403,
            "invalid_delegation",
        )
        sensitive = body("finance-agent", "finance.transfer.request", "finance-service")
        self.check("Fresh sensitive operation", finance, sensitive, 200, "authorized")
        self.check("Replayed operation", finance, sensitive, 403, "replay_rejected")
        self.check("Missing token", None, body(), 401, "authentication_failed")
        self.check(
            "Malformed identity", demo_token("bad\nidentity"), body(), 401, "authentication_failed"
        )
        self.check(
            "Unregistered proxy target",
            travel,
            body(),
            403,
            "target_not_allowed",
            "/v1/proxy/unregistered",
        )
        self.check(
            "Caller URL injection",
            travel,
            body(url="http://169.254.169.254/"),
            403,
            "invalid_request",
            "/v1/proxy/weather",
        )
        self.check("Registered weather proxy", travel, body(), 200, path="/v1/proxy/weather")
        self.check(
            "Finance admin escalation",
            finance,
            body("finance-agent", "system.admin", "system-service"),
            403,
            "capability_not_allowed",
        )
        self.check(
            "Unsigned JWT",
            jwt.encode(claims, key="", algorithm="none"),
            body(),
            401,
            "authentication_failed",
        )
        self.check(
            "Wrong issuer",
            demo_token("travel-agent", iss="other"),
            body(),
            401,
            "authentication_failed",
        )
        weather = demo_token("weather-agent")
        rate_payload = body("weather-agent", "system.health.read", "system-service")
        # Reset this quota immediately before the bounded rate sequence.
        reset_demo_quotas()
        codes = [
            self.client.post(
                "/v1/authorize", json=rate_payload, headers={"Authorization": f"Bearer {weather}"}
            ).status_code
            for _ in range(30)
        ]
        self.tokens.append(weather)
        response = self.check(
            "Identity rate limit", weather, rate_payload, 429, "rate_limit_exceeded"
        )
        self.outcomes[-1].passed &= codes == [200] * 30 and response.status_code == 429
        reset_demo_quotas()
        return self.outcomes


@app.command()
def run(json_output: bool = typer.Option(False, "--json")) -> None:
    with httpx.Client(
        base_url=LOCAL_URL, timeout=5, trust_env=False, follow_redirects=False
    ) as client:
        outcomes = Lab(client).run()
    failed = sum(not result.passed for result in outcomes)
    if json_output:
        typer.echo(json.dumps([asdict(outcome) for outcome in outcomes], indent=2))
    else:
        for result in outcomes:
            typer.echo(
                f"[{'PASS' if result.passed else 'FAIL'}] {result.scenario} "
                f"-> HTTP {result.actual_status} (expected {result.expected_status})"
            )
        typer.echo(
            f"Security scenarios: {len(outcomes)}\nExpected outcomes: {len(outcomes) - failed}"
            f"\nUnexpected outcomes: {failed}"
        )
    raise typer.Exit(1 if failed else 0)


# Keep the explicit `run` subcommand even when this app has one command.
@app.callback()
def main() -> None:
    """Safe, local-only security verification commands."""
