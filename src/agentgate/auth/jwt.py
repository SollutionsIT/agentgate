import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from agentgate.auth.identity import Identity
from agentgate.config import Settings
from agentgate.domain.decisions import GateError


class TokenVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        key = serialization.load_pem_public_key(settings.public_key_path.read_bytes())
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError("RS256 requires an RSA public key of at least 2048 bits")
        self.key = key

    def verify(self, token: str) -> Identity:
        try:
            if len(token) > 8192:
                raise ValueError("oversized credential")
            claims = jwt.decode(
                token,
                self.key,
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                audience=self.settings.audience,
                options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"], "strict_aud": True},
            )
            identity = Identity.model_validate(claims)
            if not 0 < identity.exp - identity.iat <= self.settings.max_token_lifetime:
                raise ValueError("invalid lifetime")
            if "nbf" in claims and type(claims["nbf"]) is not int:
                raise ValueError("invalid not-before")
            return identity
        except (jwt.PyJWTError, ValidationError, ValueError, TypeError) as from_error:
            raise GateError(401, "authentication_failed") from from_error
