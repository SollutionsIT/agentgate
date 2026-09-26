# Validation record — 2026-09-26

This records local implementation verification, not an independent external security audit.
All development ran inside a disposable Linux amd64 GitHub Codespace.

## Reproduction

A source-only copy was made without an existing virtual environment, keys, cache or Redis state.
Source file/directory permissions were normalized to Git checkout modes. The documented setup was
run with Python 3.12.14; the original working checkout was also tested with Python 3.14.2.
Docker ran the actual gateway, OPA 1.21.0, Redis 8.10.2 and both deterministic workloads.

Commands executed successfully:

```text
docker version
docker run --rm hello-world
docker compose version
make setup
make lint
make typecheck
make test
make policy-test
make up
make test-integration
make demo
make attack-lab
make package
make audit
docker compose ps
make down
make clean
```

| Check | Result |
| --- | --- |
| Ruff lint and formatting | Passed |
| Strict mypy | 31 runtime source files passed |
| Unit tests | 92 passed on Python 3.12 and 3.14 |
| Rego tests | 13 passed |
| Reviewed privilege baseline | 60 cases matched |
| Actual dependency integration tests | 8 passed |
| Security lab | 25 expected outcomes; zero unexpected outcomes |
| Policy matrix JSON | 60 parseable cases |
| Policy diff CLI | Deliberate finance privilege expansion detected; exit 1 |
| Source distribution and wheel | Built; Twine validation passed |
| Distribution contents | License present; no private keys or generated runtime artifacts |
| Locked runtime dependency audit | No known vulnerabilities reported at validation time |
| Workflow syntax | actionlint 1.7.12 passed both workflows |
| Compose health | All five services healthy before shutdown |

The integration suite verified exact failures during OPA and Redis outages, replay state after Redis
restart, one successful nonce consumption under 20 concurrent attempts, an exact 30-request identity
quota under 40 concurrent attempts, token-rotation resistance, metrics increments, audit redaction,
downstream failure handling and demo network/key isolation.

The 25 lab cases cover unknown identity, expired JWT, wrong audience/key/issuer, token tampering,
unsigned JWT, forbidden/unknown capabilities, subject impersonation, over-delegation, valid grant
creation/use, scope escalation, short-lived grant creation/expiry, fresh and replayed sensitive
operations, missing/malformed identity, unregistered targets, caller URL injection, a successful
weather proxy, finance-to-admin escalation and rate limiting.

## Review and fixes

The implementation was reviewed from Python engineering, application security, IAM, DevSecOps and
maintainer perspectives. Material findings were fixed and affected checks rerun:

- Subject identity is bound to the verified JWT; JWT algorithm, issuer, audience and lifetime are
  enforced independently of policy. Unknown capabilities/resources are rejected before OPA.
- Delegation rechecks current ownership and delegation policy; it cannot chain, broaden scope or
  outlive the issuer credential. Nonces cannot be reset by rotating an access token.
- Redis operations are atomic, persistent and non-evicting; outages block enforcement. Readiness
  verifies the loaded policy rather than only process existence.
- Proxy routing is entirely server-owned. Redirects are rejected. Shared-client cookies are
  suppressed to prevent downstream sessions crossing agent identities. Responses have byte and
  total-time bounds; audit fields and metric labels remain bounded and credential-free.
- Demo workloads have separate networks from control-plane services and from one another. Containers
  run unprivileged. Keys never enter images. Only the gateway publishes a loopback development port.
- A dependency-recovery race in test teardown was fixed by waiting for downstream health. Explicit
  lint exclusions make source-archive checks work without Git metadata. Packaging tools are locked,
  and archive contents are checked for generated artifacts and private keys.
- The README was reviewed for immediate product purpose, boundaries, setup accuracy and brevity
  (199 lines). Threat-model limitations are explicit; there are no claims of complete agent safety.

## Codespace environment corrections

Docker socket permissions were already correct outside the Codex sandbox: root:docker, mode 0660,
with the Codespace user in the docker group. Approved Docker execution resolved the sandbox-only
access error. No chmod 666 or personal-computer changes were used.

The Codespace also retained a legacy iptables forwarding DROP policy while Docker used nftables.
The repository helper handles this specific Codespaces conflict with same-bridge rules for named
AgentGate bridges; it does not change global policy. Cleanup removes these rules. A gateway-only edge
network enables the loopback port binding while workload/control networks remain internal.

## Limits of this verification

Hosted GitHub Actions and CodeQL have not executed remotely; their workflows were statically validated
and Action SHAs resolved from official repositories. ARM64 runtime execution was not tested. The test
client currently emits one upstream Starlette HTTPX deprecation warning; all tests pass without hiding it.
Dependency auditing is a point-in-time check, not a guarantee of vulnerability absence. No external
security audit, production issuer integration or production deployment validation is claimed.

Final cleanup removes demo containers, networks, Redis volumes, generated keys, logs, test/build caches
and temporary reproduction artifacts. Source, tests, lockfile, policies and setup instructions remain.
