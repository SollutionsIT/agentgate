import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agentgate.auth.jwt import TokenVerifier
from agentgate.domain.decisions import GateError


def test_valid_identity(settings, token):
    assert TokenVerifier(settings).verify(token()).sub == "travel-agent"


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "other"},
        {"aud": "other"},
        {"aud": ["agentgate", "other"]},
        {"exp": 1},
        {"nbf": 9999999999},
        {"iat": 9999999999},
        {"sub": "../../admin"},
        {"sub": "admin\nagent"},
        {"sub": 123},
        {"jti": "short"},
        {"jti": None},
        {"iat": 0},
        {"exp": "9999999999"},
        {"nbf": "0"},
        {"exp": True},
        {"exp": None},
        {"sub": None},
    ],
)
def test_bad_claims(settings, token, claims):
    with pytest.raises(GateError) as error:
        TokenVerifier(settings).verify(token(**claims))
    assert error.value.status == 401


@pytest.mark.parametrize("missing", ["sub", "iss", "aud", "exp", "iat", "jti"])
def test_missing_claim(settings, token, keys, missing):
    claims = jwt.decode(token(), options={"verify_signature": False})
    del claims[missing]
    with pytest.raises(GateError):
        TokenVerifier(settings).verify(jwt.encode(claims, keys[0], algorithm="RS256"))


def test_wrong_key_and_algorithms(settings, token):
    claims = jwt.decode(token(), options={"verify_signature": False})
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = [
        jwt.encode(claims, wrong, algorithm="RS256"),
        jwt.encode(claims, "a" * 64, algorithm="HS256"),
        jwt.encode(claims, "", algorithm="none"),
        "not-a-token",
        "a" * 9000,
    ]
    for value in forged:
        with pytest.raises(GateError):
            TokenVerifier(settings).verify(value)


def test_nbf_optional(settings, token, keys):
    claims = jwt.decode(token(), options={"verify_signature": False})
    del claims["nbf"]
    assert TokenVerifier(settings).verify(jwt.encode(claims, keys[0], algorithm="RS256"))


def test_expired_real_timestamp(settings, token):
    now = int(time.time())
    with pytest.raises(GateError):
        TokenVerifier(settings).verify(token(iat=now - 120, nbf=now - 120, exp=now - 60))


def test_weak_or_wrong_key_type_rejected(settings):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    for key in (
        rsa.generate_private_key(public_exponent=65537, key_size=1024),  # noqa: S505 - rejection test
        ec.generate_private_key(ec.SECP256R1()),
    ):
        settings.public_key_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        with pytest.raises(ValueError, match="RSA public key"):
            TokenVerifier(settings)
