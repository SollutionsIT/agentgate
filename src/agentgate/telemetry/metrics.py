from prometheus_client import Counter, Histogram

REQUESTS = Counter("agentgate_requests_total", "Protected requests")
DECISIONS = Counter("agentgate_authorization_decisions_total", "Policy decisions", ["decision"])
AUTH_FAILURES = Counter("agentgate_authentication_failures_total", "Invalid credentials")
REPLAYS = Counter("agentgate_replay_rejections_total", "Reused operation nonces")
RATE_REJECTIONS = Counter("agentgate_rate_limit_rejections_total", "Identity quota exceeded")
POLICY_SECONDS = Histogram("agentgate_policy_evaluation_seconds", "OPA evaluation latency")
PROXY = Counter("agentgate_proxy_requests_total", "Forwarded requests", ["outcome"])
