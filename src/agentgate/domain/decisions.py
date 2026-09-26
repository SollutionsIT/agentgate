from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Decision(BaseModel):
    decision: Literal["allow", "deny"]
    reason: str
    policy_id: str = "agentgate-v1"
    decision_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GateError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        self.decision = Decision(decision="deny", reason=reason)
        self.status = status
        self.reason = reason
        super().__init__(reason)
