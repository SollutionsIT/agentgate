# Security design and operating boundaries

## Authentication and policy

The gateway uses PyJWT with a configured RSA public key (at least 2048 bits) and a fixed RS256
algorithm list. It requires `iss`, `aud`, `exp`, `iat`, `sub` and `jti`, validates `nbf` when present,
rejects non-integer time claims and imposes a maximum lifetime (900 seconds by default).
There is no token-selected key URL or algorithm. JWT claims identify callers; permission claims are ignored.
Unknown identities have no grant in Rego. A request's subject must equal the verified token subject.

The Python capability catalog prevents unknown names or mismatched resources reaching OPA. OPA
independently constrains capabilities and resources. Policy input uses verified identity and configured
environment; a conflicting caller environment is denied. Only a literal boolean OPA result is accepted.
`/ready` checks Redis and the loaded policy's readiness rule. A ready process does not guarantee downstream uptime.

The policy bundle enables development only. Operators deploying another environment must review and
configure both the gateway environment and the policy. Rule names and target origins are server-owned.

## Replay, rate limits and storage

Sensitive capabilities (`booking.create`, `finance.transfer.request`, `profile.update`, `system.admin`)
and delegation creation require a UUID nonce. Redis atomically consumes the identity/nonce combination.
Changing tokens, capabilities or resources cannot reuse that nonce within retention. Token `jti` is
validated for credential identity, but access tokens are deliberately reusable for ordinary reads.

Retention is `max(replay_window, remaining_access_token_lifetime)`. Replaying after this bounded period,
or submitting a new nonce with a stolen credential, is not prevented. Non-sensitive reads have no nonce
consumption. `/v1/authorize` consumes a sensitive nonce too: use a different nonce for a later proxy call.
The gateway consumes before forwarding; a timeout may burn a nonce even if the downstream did not act.
Never automatically retry non-idempotent operations with a new nonce without application reconciliation.

Rate limits use an atomic Lua INCR/EXPIRE operation with a fixed window beginning at the first request.
All authenticated attempts consume quota, including denials. Reissuing tokens does not reset an agent's
quota. Boundary bursts can approach twice the quota across adjacent windows. Invalid-token floods need
upstream IP/connection limits. No in-memory security fallback exists.

Redis uses a persistent volume, AOF with `appendfsync always`, and `noeviction`. Storage errors fail
closed. Ordinary `make down` preserves state; `make clean` intentionally deletes it. Restore/rollback,
operator deletion, disk loss or Redis compromise can invalidate replay guarantees. Production durability
and replication semantics must be reviewed; a local volume is not a high-availability design.

## Delegation

`POST /v1/delegations` creates a random grant ID stored in Redis. It is an opaque reference, not a bearer
credential: the delegatee must present its own valid JWT. Only travel-agent may delegate weather.read
on weather-service to planner-agent under the bundled policy. Having an ordinary capability does not
imply permission to delegate it.

Grants cannot exceed five minutes or the issuer credential's remaining lifetime. Use checks the exact
recipient, capability, resource, environment and expiry, then reevaluates the delegator's current own
permission and current delegation policy. There is no chain or redelegation using delegated rights.
Policy removal revokes subsequent uses. Token revocation and a dedicated grant-revocation API are not
implemented; expiry and policy withdrawal are the available controls.

## Proxy and transport

Three registry entries bind one capability and resource each to a fixed origin, path and HTTP method.
No URL, path, method, body, query, cookie or authorization header from callers is forwarded. HTTPX does
not follow redirects or trust environment proxy variables. A blank Cookie override prevents the
shared HTTP client from carrying downstream sessions across identities. Downstream output is limited
to 64 KiB and five seconds total;
non-200 responses and failures return a generic 502. Incoming bodies are limited to 16 KiB.
This intentionally small proxy supports the deterministic demo operations, not arbitrary API payloads.

Compose separates control, weather and finance networks. Only the gateway joins all three; all networks
are internal except a gateway-only edge network that supports the loopback port binding.
No internal service publishes a host port. Containers run unprivileged with capability
sets dropped, process/memory limits and no-new-privileges; application and OPA roots are read-only.
Redis writes only its required state volume. The gateway's loopback HTTP endpoint is for local development.
Use TLS, authenticated infrastructure and protected management endpoints before exposing a deployment.
Codespaces port forwarding should remain private.

## Audit and metrics

JSON events allowlist fields and omit credentials, keys, headers and payloads. Validation errors are
redacted instead of returning FastAPI's input-echoing diagnostics. Decision IDs correlate successful
and denied policy decisions. Authentication failures have generated request IDs; they do not log an
untrusted identity. Uvicorn access logging is disabled because paths and query strings are caller-controlled.
Prometheus labels are fixed enumerations, never arbitrary identity/capability strings.

Audit stdout is observable evidence for the local lab, not a durable, tamper-proof ledger. Production
needs a secured collector and retention policy. Liveness/readiness/metrics are intentionally public on
the loopback endpoint; restrict them at ingress in a deployment. No telemetry leaves the lab.

## Policy tooling and supply chain

`policy test` runs OPA tests and the committed baseline; it never regenerates the baseline automatically.
`policy diff` evaluates both files with the real OPA binary over known and sentinel identities and
capabilities, all catalog resources plus an unknown resource, three environment values, and known/unknown
recipient choices. It compares both allow and can_delegate. It is a finite regression tool, not a theorem
prover. Add cases when adding semantic policy inputs. Untrusted candidate policies must not be executed
as privileged code; use CI/container isolation for third-party contributions.

`uv.lock` fixes Python dependencies. Runtime images and Actions use verified digests/commits. Setup
verifies the OPA binary against repository-pinned SHA-256 hashes. Dependabot and dependency auditing
support updates; pinned software still needs maintenance. Design references:
[PyJWT validation](https://pyjwt.readthedocs.io/en/stable/api.html),
[OPA default rules](https://www.openpolicyagent.org/docs/policy-reference/keywords/default), and
[Redis atomic rate limits](https://redis.io/docs/latest/commands/incr/).
