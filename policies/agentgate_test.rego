package agentgate_test

import rego.v1
import data.agentgate

request(agent, action, resource) := {
  "subject": {"agent_id": agent}, "action": action, "resource": resource,
  "context": {"environment": "development"},
}

test_travel_weather if {
  agentgate.allow with input as request("travel-agent", "weather.read", "weather-service")
}

test_finance_balance if {
  agentgate.allow with input as request("finance-agent", "finance.balance.read", "finance-service")
}

test_forbidden_transfer if {
  not agentgate.allow with input as request("travel-agent", "finance.transfer.request", "finance-service")
}

test_forbidden_admin if {
  not agentgate.allow with input as request("finance-agent", "system.admin", "system-service")
}

test_unknown_agent if {
  not agentgate.allow with input as request("unknown-agent", "weather.read", "weather-service")
}

test_unknown_capability if {
  not agentgate.allow with input as request("admin-agent", "secrets.read", "secret-service")
}

test_default_deny if { not agentgate.allow with input as {} }

test_wrong_resource if {
  not agentgate.allow with input as request("travel-agent", "weather.read", "finance-service")
}

test_wrong_environment if {
  not agentgate.allow with input as {"subject": {"agent_id": "admin-agent"},
    "action": "system.admin", "resource": "system-service", "context": {"environment": "production"}}
}

test_valid_delegation if {
  req := object.union(request("travel-agent", "weather.read", "weather-service"), {"delegatee": "planner-agent"})
  agentgate.can_delegate with input as req
}

test_over_delegation if {
  req := object.union(request("travel-agent", "finance.transfer.request", "finance-service"), {"delegatee": "planner-agent"})
  not agentgate.can_delegate with input as req
}

test_ownership_not_delegation if {
  req := object.union(request("finance-agent", "finance.transfer.request", "finance-service"), {"delegatee": "planner-agent"})
  not agentgate.can_delegate with input as req
}

test_unknown_delegatee if {
  req := object.union(request("travel-agent", "weather.read", "weather-service"), {"delegatee": "unknown-agent"})
  not agentgate.can_delegate with input as req
}
