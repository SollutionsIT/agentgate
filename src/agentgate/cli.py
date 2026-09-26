import json
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import typer

from agentgate.policy.loader import AGENTS, OPA, POLICY, compare, evaluate

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    help="AgentGate local development and policy verification tools.",
)
policy_app = typer.Typer(
    pretty_exceptions_show_locals=False, help="Evaluate real Rego and detect privilege expansion."
)
token_app = typer.Typer(
    pretty_exceptions_show_locals=False,
    help="Development-only credentials; never an identity provider.",
)
audit_app = typer.Typer(
    pretty_exceptions_show_locals=False, help="Read the local Compose audit stream."
)
app.add_typer(policy_app, name="policy")
app.add_typer(token_app, name="token")
app.add_typer(audit_app, name="audit")
LOCAL_URL = "http://127.0.0.1:8080"


def demo_token(agent: str, **overrides: object) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "sub": agent,
        "iss": "agentgate-demo",
        "aud": "agentgate",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid4().hex,
    }
    claims.update(overrides)
    return jwt.encode(claims, Path(".local/keys/private.pem").read_bytes(), algorithm="RS256")


@token_app.command("issue-demo")
def issue_demo(agent: str = typer.Option(..., help="Registered demo agent identity")) -> None:
    if agent not in AGENTS:
        raise typer.BadParameter("Unknown demo agent")
    typer.echo(demo_token(agent))


@app.command()
def status() -> None:
    with httpx.Client(base_url=LOCAL_URL, timeout=5, trust_env=False) as client:
        response = client.get("/ready")
        typer.echo(response.text)
        raise typer.Exit(0 if response.status_code == 200 else 1)


@policy_app.command()
def matrix(json_output: bool = typer.Option(False, "--json")) -> None:
    rows = evaluate(POLICY)
    if json_output:
        typer.echo(json.dumps(rows, indent=2))
    else:
        typer.echo(f"{'AGENT':<16} {'CAPABILITY':<27} RESULT")
        for row in rows:
            typer.echo(
                f"{row['input']['subject']['agent_id']:<16} "
                f"{row['input']['action']:<27} {'ALLOW' if row['allow'] else 'DENY'}"
            )


@policy_app.command("test")
def policy_test() -> None:
    result = subprocess.run(  # noqa: S603 - fixed local OPA invocation
        [str(OPA.resolve()), "test", "policies", "--verbose"],  # noqa: S603
        check=False,
    )
    if result.returncode:
        raise typer.Exit(result.returncode)
    baseline = json.loads(Path("policies/baseline.json").read_text())
    rows = evaluate(POLICY)
    observed = {
        agent: sorted(
            row["input"]["action"]
            for row in rows
            if row["allow"] and row["input"]["subject"]["agent_id"] == agent
        )
        for agent in [*AGENTS, "unknown-agent"]
    }
    if baseline != observed:
        typer.echo("FAIL: privilege matrix differs from the reviewed baseline.", err=True)
        typer.echo(json.dumps(observed, indent=2), err=True)
        raise typer.Exit(1)
    typer.echo(f"PASS: {len(rows)} authorization cases match the reviewed baseline.")


@policy_app.command()
def diff(old: Path, new: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    changes = compare(old, new)
    if json_output:
        typer.echo(json.dumps(changes, indent=2))
    else:
        for heading, rows in changes.items():
            typer.echo(f"{heading.upper().replace('_', ' ')}: {len(rows)}")
            for row in rows:
                typer.echo(json.dumps(row, sort_keys=True))
    # CI gate: expansion is security relevant even when removals occur simultaneously.
    raise typer.Exit(1 if changes["newly_allowed"] else 0)


@audit_app.command("tail")
def audit_tail() -> None:
    raise typer.Exit(
        subprocess.run(  # noqa: S603,S607 - fixed operator command
            ["docker", "compose", "logs", "--follow", "--no-log-prefix", "gateway"],  # noqa: S607
            check=False,
        ).returncode
    )
