from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTGATE_", extra="forbid")
    environment: Literal["development", "production"] = "development"
    public_key_path: Path = Path(".local/keys/public.pem")
    issuer: str = Field(default="agentgate-demo", min_length=1)
    audience: str = Field(default="agentgate", min_length=1)
    opa_url: str = "http://opa:8181"
    redis_url: str = "redis://redis:6379/0"
    weather_url: str = "http://weather:8001"
    finance_url: str = "http://finance:8001"
    rate_limit: int = Field(default=30, ge=1, le=10000)
    rate_window: int = Field(default=60, ge=1, le=3600)
    replay_window: int = Field(default=300, ge=1, le=3600)
    max_token_lifetime: int = Field(default=900, ge=1, le=3600)

    @field_validator("opa_url", "weather_url", "finance_url")
    @classmethod
    def service_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("expected an operator-configured HTTP origin")
        return value.rstrip("/")

    @field_validator("redis_url")
    @classmethod
    def redis_origin(cls, value: str) -> str:
        if urlsplit(value).scheme not in {"redis", "rediss"}:
            raise ValueError("expected redis or rediss URL")
        return value
