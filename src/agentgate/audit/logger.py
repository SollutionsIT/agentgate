import json
import logging
from datetime import UTC, datetime
from uuid import uuid4

LOGGER = logging.getLogger("agentgate.audit")
# Allowlist prevents payloads/headers/credentials from entering the audit stream.
FIELDS = {
    "decision_id",
    "request_id",
    "agent_id",
    "action",
    "resource",
    "decision",
    "reason",
    "delegation_id",
    "delegatee",
}


def audit(event: str, **fields: object) -> None:
    record = {"event": event, "timestamp": datetime.now(UTC).isoformat(), "event_id": str(uuid4())}
    record.update({key: str(value) for key, value in fields.items() if key in FIELDS})
    LOGGER.info(json.dumps(record, separators=(",", ":")))


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.handlers = [handler]
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
