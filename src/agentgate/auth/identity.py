from pydantic import BaseModel, ConfigDict, Field

from agentgate.domain.requests import AgentID


class Identity(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    sub: AgentID
    jti: str = Field(pattern=r"^[a-zA-Z0-9_-]{16,128}$")
    iat: int
    exp: int
