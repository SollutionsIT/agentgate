# Local API examples

Run `make setup && make up` inside the Codespace, then activate `.venv`.
All credentials below are development-only and expire after five minutes.

```bash
source .venv/bin/activate
TRAVEL="$(agentgate token issue-demo --agent travel-agent)"
PLANNER="$(agentgate token issue-demo --agent planner-agent)"
FINANCE="$(agentgate token issue-demo --agent finance-agent)"
```

## Registered weather request

```bash
curl -sS http://127.0.0.1:8080/v1/proxy/weather \
  -H "Authorization: Bearer $TRAVEL" -H 'Content-Type: application/json' \
  -d '{"subject":{"agent_id":"travel-agent"},"action":"weather.read","resource":"weather-service"}'
```

## Sensitive preview and replay

```bash
NONCE="$(python -c 'import uuid; print(uuid.uuid4())')"
curl -sS http://127.0.0.1:8080/v1/proxy/transfer-preview \
  -H "Authorization: Bearer $FINANCE" -H 'Content-Type: application/json' \
  -d "{\"subject\":{\"agent_id\":\"finance-agent\"},\"action\":\"finance.transfer.request\",\"resource\":\"finance-service\",\"context\":{\"nonce\":\"$NONCE\"}}"
```

The first request returns a deterministic preview with `money_moved: false`.
Repeating the same request returns 403 `replay_rejected`.

## Explicit delegation

```bash
NONCE="$(python -c 'import uuid; print(uuid.uuid4())')"
GRANT="$(curl -fsS http://127.0.0.1:8080/v1/delegations \
  -H "Authorization: Bearer $TRAVEL" -H 'Content-Type: application/json' \
  -d "{\"delegatee\":\"planner-agent\",\"action\":\"weather.read\",\"resource\":\"weather-service\",\"ttl_seconds\":120,\"context\":{\"nonce\":\"$NONCE\"}}" \
  | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
curl -sS http://127.0.0.1:8080/v1/proxy/weather \
  -H "Authorization: Bearer $PLANNER" -H 'Content-Type: application/json' \
  -d "{\"subject\":{\"agent_id\":\"planner-agent\"},\"action\":\"weather.read\",\"resource\":\"weather-service\",\"delegation_id\":\"$GRANT\"}"
```

The planner authenticates with its own credential. The grant cannot authorize a different recipient,
capability or resource, cannot be redelegated, and stops working after expiry or policy withdrawal.

## Metrics and audit

```bash
curl -sS http://127.0.0.1:8080/metrics
agentgate audit tail
```

Audit records omit tokens, keys, request bodies and authorization headers.
