# Contributing

Use a Linux Codespace (amd64 or arm64), Python 3.12+ with venv, curl, make, Docker and Compose v2+.
Development and bootstrap dependencies stay under the checkout. No host-machine setup is required.

```bash
make setup
make lint typecheck test policy-test
make up
make test-integration
make demo attack-lab
make package audit
make down
```

Integration tests and the lab own the disposable `agentgate` Compose project for their duration.
Do not run them concurrently or against a deployment containing useful data. Tests reset demo quotas
and temporarily stop OPA, Redis and weather; Redis replay state should survive ordinary restarts.
Use `make clean` to remove containers, volumes, demo keys and generated output after testing.

## Layout

- `src/agentgate/api`: thin HTTP routes, dependencies and input-size enforcement.
- `auth`, `authorization`, `policy`: identity verification, capabilities and Rego integration.
- `security`: shared replay/rate controls and bounded delegation.
- `services/gateway.py`: orchestration and proxy enforcement.
- `audit`, `telemetry`, `domain`: event output, bounded metrics and request/decision models.
- `policies`: executable Rego, negative tests and reviewed privilege baseline.
- `examples`: deterministic protected workloads and request examples.
- `tests/unit`, `tests/integration`: isolated controls and actual local dependency tests.

## Review expectations

Keep business decisions out of HTTP routes. Add an explicit capability/resource mapping and Rego rule
for new operations; never infer a permission from caller-provided claims. Include denial, outage and
escalation cases for security-sensitive changes. Do not update the policy baseline merely to make a
failing test green: describe each added privilege and its intended recipient in the pull request.

Use `.venv/bin/ruff format .` to format and `.venv/bin/mypy` for strict runtime-code type checking.
To update dependencies, run `.bootstrap/bin/uv lock --upgrade`, `make setup`, and all checks above.
Review the resulting lock and vulnerability audit. To update OPA, verify release binary checksums,
update setup hashes and the Compose digest together, then rerun Rego and integration tests.

The CLI's policy commands operate from the repository root. A built wheel contains the runtime and
CLI; the repository supplies reviewed policy, Compose and setup artifacts. GitHub Actions use immutable
commit pins; Dependabot proposes updates. The CodeQL workflow requires GitHub code scanning support
(public repositories are supported). Enable private vulnerability reporting in repository settings.

## Docker access in Codespaces

Check `id`, `stat /var/run/docker.sock` and `docker version`. A normal Codespace user should belong to
the socket's Docker group. Do not make the socket world-writable. If a tooling sandbox masks existing
membership or denies socket access, approve the Docker operation through that tool's normal permission
flow. This checkout needed no group changes; the standard Codespace terminal already had access.

Some disposable Codespaces retain an iptables-legacy forwarding DROP policy after Docker switches to
nftables. `make up` detects this specific combination in Codespaces and uses passwordless sudo to add
same-bridge accept rules only for the four named AgentGate bridges. Docker's nft isolation remains
active. `make down` and `make clean` remove those rules. No socket permission or global firewall policy
is changed. The helper does nothing outside Codespaces or when the conflict is absent.

## Licensing

Contributions are accepted under Apache-2.0. Never include private keys, credentials, environment files,
virtual environments or generated test output in a pull request.
