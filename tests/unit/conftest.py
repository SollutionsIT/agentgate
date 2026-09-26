import time
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agentgate.config import Settings


@pytest.fixture(scope="session")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture
def settings(tmp_path, keys):
    public = tmp_path / "public.pem"
    public.write_bytes(keys[1])
    return Settings(public_key_path=public)


@pytest.fixture
def token(keys):
    def issue(**overrides):
        now = int(time.time())
        claims = {
            "iss": "agentgate-demo",
            "aud": "agentgate",
            "sub": "travel-agent",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid4().hex,
        }
        claims.update(overrides)
        return jwt.encode(claims, keys[0], algorithm="RS256")

    return issue
