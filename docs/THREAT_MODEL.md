# Threat model

AgentGate is an authorization and policy enforcement layer. It does not make AI agents trustworthy,
prevent prompt injection inside agents, or protect interfaces reachable outside the gateway.
The trust boundary is the protected HTTP interface and its operator-controlled policy/target registry.

## Assets and actors

Assets are agent identities, issuer signing keys, authorization policies, delegated capabilities,
downstream workloads, replay/rate state and audit records.
Threat actors include compromised or malicious agents, buggy autonomous agents, holders of stolen
or expired tokens, and developers who accidentally broaden a policy or expose infrastructure.
The host administrator, issuer and policy deployment authority are trusted; their compromise is out of scope.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Impersonation / tampering | RSA signature, fixed RS256, strict issuer/audience, required expiry and identity | A stolen live bearer credential remains usable |
| Replay | Atomic identity/nonce SET NX with expiry; persistent Redis AOF; no eviction | Fresh nonces on a stolen token; state loss; replay after retention |
| Privilege escalation | Deny-by-default Rego, explicit capability/resource catalog, authenticated subject binding | A deliberately permissive operator policy remains authoritative |
| Excessive delegation | Explicit recipient/capability/resource grant, five-minute ceiling, issuer-token expiry ceiling, current-policy recheck | A compromised authorized delegator can issue permitted grants |
| Confused deputy | Grant recipient authenticated independently; fixed proxy method/path/resource binding | Downstream business semantics remain the workload's responsibility |
| Policy bypass | Every proxy call reauthorizes; no caller-supplied authorization tickets | Direct downstream access outside gateway network controls |
| SSRF / arbitrary proxy | Static operator registry, no caller URL/query/header forwarding, no redirects, bounded responses | Malicious operator configuration or compromised infrastructure DNS |
| Authorization drift | Real Rego tests, reviewed matrix, finite-domain policy diff including delegation | Untested future identities/contexts; not formal verification |
| Log secret leakage / injection | Allowlisted fields, validated identifiers, JSON escaping, generic errors, no access logs | Operators can still enable unsafe logging outside the application |
| Denial of service | Per-identity atomic quota, body/response limits, concurrency cap, dependency timeouts, container limits | Unauthenticated floods and slow bodies require ingress controls |
| Infrastructure fail-open | Missing/nonboolean policy result, policy exception or Redis failure blocks protected work | Availability loss is intentional; operators must not bypass the gateway |
| Audit tampering/loss | Structured stream with decision/event IDs; no credentials | Local stdout is not tamper-evident or durable evidence storage |

## Boundaries and assumptions

The public verification key is mounted read-only. The private demo key stays outside every container.
The demo services have no real data or money movement. Only the gateway is published to loopback.
Network separation prevents demo workloads from directly addressing policy/storage or each other.
OPA and Redis are trusted internal components; their demo APIs are not externally published.
A hostile host or administrator with Docker access can replace policy, read state and bypass these controls.

Production requires authenticated/encrypted service links, protected policy administration, a managed
issuer, durable replay state, external audit collection and network rules that make the gateway the
only route to protected tools. The development policy denies production context until explicitly reviewed.

## Non-goals

Prompt classification, model alignment, malware detection, risk scoring, identity-provider operation,
financial transaction safety, anonymous Internet-scale DoS protection, and universal exactly-once
execution are not provided. There is no guarantee that permitted actions are wise or that responses
from a downstream service are truthful.
