# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Supported on the default branch |
| Unreleased branches or older versions | No support commitment |

This is an early public project with a tested local demonstration deployment. It has not received an
independent external security audit or a production readiness certification.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** private reporting flow if enabled:
https://github.com/SollutionsIT/agentgate/security/advisories/new

If private reporting is unavailable, open a minimal issue requesting a private contact channel without
including exploit details, credentials or sensitive information. Do not publish active credentials or
attack third-party systems to demonstrate impact. There is no guaranteed response SLA or bug bounty.

Include the affected version, expected and observed behavior, a minimal local reproduction, impact,
and suggested mitigations. The deterministic demo environment is the preferred reproduction target.

## Security design

AgentGate separates authentication from authorization, denies unknown privileges, restricts delegation,
uses atomic distributed replay/rate state and fails closed when policy/storage is unavailable.
Private signing keys are never part of the container image or repository. The development CLI's token
issuer must not be used as a production identity provider.

Read [the threat model](docs/THREAT_MODEL.md) and [security semantics](docs/SECURITY_DESIGN.md) before deployment.
Never expose the demo's OPA or Redis interfaces. Protect downstream services from direct access.
Do not treat authorization as protection against prompt injection or harmful but permitted actions.
