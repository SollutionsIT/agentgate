package agentgate

import rego.v1

default allow := false
default can_delegate := false
ready := true

agents := {"travel-agent", "weather-agent", "finance-agent", "admin-agent", "planner-agent"}

resources := {
  "weather.read": "weather-service",
  "booking.search": "booking-service",
  "booking.create": "booking-service",
  "finance.balance.read": "finance-service",
  "finance.transfer.request": "finance-service",
  "profile.read": "profile-service",
  "profile.update": "profile-service",
  "system.health.read": "system-service",
  "system.admin": "system-service",
}

permissions := {
  "travel-agent": {"weather.read", "booking.search"},
  "weather-agent": {"system.health.read"},
  "finance-agent": {"finance.balance.read", "finance.transfer.request"},
  "planner-agent": {"booking.search"},
  "admin-agent": {"weather.read", "booking.search", "booking.create", "finance.balance.read",
                  "finance.transfer.request", "profile.read", "profile.update",
                  "system.health.read", "system.admin"},
}

# Environment comes from the gateway, never solely from caller context.
# This checked-in bundle intentionally enables the local development environment only.
allow if {
  input.context.environment == "development"
  input.subject.agent_id in agents
  input.action in permissions[input.subject.agent_id]
  resources[input.action] == input.resource
}

# Explicit, one-hop delegation. Owning a permission alone does not confer delegation rights.
can_delegate if {
  allow
  input.subject.agent_id == "travel-agent"
  input.delegatee == "planner-agent"
  input.delegatee in agents
  input.action == "weather.read"
  input.resource == "weather-service"
}
