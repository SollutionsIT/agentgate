"""The positive path and a capability denial through the running local gateway."""

import httpx

from agentgate.cli import LOCAL_URL, demo_token

with httpx.Client(base_url=LOCAL_URL, trust_env=False, timeout=5) as client:
    headers = {"Authorization": f"Bearer {demo_token('travel-agent')}"}
    for action, resource, path, expected in [
        ("weather.read", "weather-service", "/v1/proxy/weather", 200),
        ("finance.transfer.request", "finance-service", "/v1/authorize", 403),
    ]:
        response = client.post(
            path,
            headers=headers,
            json={
                "subject": {"agent_id": "travel-agent"},
                "action": action,
                "resource": resource,
            },
        )
        assert response.status_code == expected, response.text
        print(f"travel-agent -> {action}: {'ALLOW' if expected == 200 else 'DENY'}")
        print(response.text)
