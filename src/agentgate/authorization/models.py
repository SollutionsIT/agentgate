from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    resource: str
    sensitive: bool = False


CAPABILITIES = {
    "weather.read": Capability("weather-service"),
    "booking.search": Capability("booking-service"),
    "booking.create": Capability("booking-service", True),
    "finance.balance.read": Capability("finance-service"),
    "finance.transfer.request": Capability("finance-service", True),
    "profile.read": Capability("profile-service"),
    "profile.update": Capability("profile-service", True),
    "system.health.read": Capability("system-service"),
    "system.admin": Capability("system-service", True),
}
