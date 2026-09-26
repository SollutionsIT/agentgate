"""Evaluate actual Rego with the verified local OPA binary, never a Python policy imitation."""

import json
import subprocess
from pathlib import Path
from typing import Any

from agentgate.authorization.models import CAPABILITIES

AGENTS = ["travel-agent", "weather-agent", "finance-agent", "admin-agent", "planner-agent"]
OPA = Path(".local/bin/opa")
POLICY = Path("policies/agentgate.rego")


def cases(full: bool = False) -> list[dict[str, Any]]:
    rows = []
    actions = {key: value.resource for key, value in CAPABILITIES.items()}
    actions["secrets.read"] = "secret-service"
    for agent in [*AGENTS, "unknown-agent"]:
        for action, resource in actions.items():
            for environment in (
                ["development", "production", "unknown"] if full else ["development"]
            ):
                for target in (
                    sorted({c.resource for c in CAPABILITIES.values()} | {"unknown-service"})
                    if full
                    else [resource]
                ):
                    for delegatee in [None, *AGENTS, "unknown-agent"] if full else [None]:
                        row: dict[str, Any] = {
                            "subject": {"agent_id": agent},
                            "action": action,
                            "resource": target,
                            "context": {"environment": environment},
                        }
                        if delegatee is not None:
                            row["delegatee"] = delegatee
                        rows.append(row)
    return rows


def evaluate(policy: Path, full: bool = False) -> list[dict[str, Any]]:
    if not OPA.is_file() or not policy.is_file():
        raise RuntimeError("Run make setup; provide an existing Rego policy file.")
    query = (
        '[{"input": row, "allow": allowed, "can_delegate": delegated} | '
        "row := input[_]; allowed := data.agentgate.allow with input as row; "
        "delegated := data.agentgate.can_delegate with input as row]"
    )
    inputs = cases(full)
    result = subprocess.run(  # noqa: S603 - fixed binary; policy paths are operator CLI arguments
        [
            str(OPA.resolve()),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(policy.resolve()),
            query,
        ],
        input=json.dumps(inputs),
        text=True,
        capture_output=True,
        timeout=60,
        check=True,
    )
    rows: list[dict[str, Any]] = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
    if len(rows) != len(inputs) or any(
        type(row.get("allow")) is not bool or type(row.get("can_delegate")) is not bool
        for row in rows
    ):
        raise RuntimeError("Policy must produce explicit boolean allow and can_delegate decisions.")
    return rows


def compare(old: Path, new: Path) -> dict[str, list[dict[str, Any]]]:
    def index(path: Path) -> dict[str, dict[str, Any]]:
        return {json.dumps(row["input"], sort_keys=True): row for row in evaluate(path, full=True)}

    before, after = index(old), index(new)
    if before.keys() != after.keys():
        raise RuntimeError("Incomplete comparison domain")
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for key, row in after.items():
        for control in ("allow", "can_delegate"):
            if row[control] != before[key][control]:
                change = {"control": control, **row["input"]}
                (added if row[control] else removed).append(change)
    return {"newly_allowed": added, "removed": removed}
