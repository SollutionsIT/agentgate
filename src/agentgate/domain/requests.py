from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

AgentID = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
CapabilityName = Annotated[
    str, Field(pattern=r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){1,4}$", max_length=96)
]
ResourceName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Subject(StrictModel):
    agent_id: AgentID


class Context(StrictModel):
    request_id: UUID = Field(default_factory=uuid4)
    environment: Literal["development", "production"] = "development"
    nonce: UUID | None = None


class AuthorizationRequest(StrictModel):
    subject: Subject
    action: CapabilityName
    resource: ResourceName
    context: Context = Field(default_factory=Context)
    delegation_id: UUID | None = None


class DelegationRequest(StrictModel):
    delegatee: AgentID
    action: CapabilityName
    resource: ResourceName
    ttl_seconds: int = Field(default=120, ge=1, le=300, strict=True)
    context: Context = Field(default_factory=Context)
