"""Generate local-only demo keys. Never overwrite an existing pair."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

folder = Path(".local/keys")
folder.mkdir(parents=True, exist_ok=True)
private = folder / "private.pem"
public = folder / "public.pem"
if private.exists() != public.exists():
    raise SystemExit("Incomplete key pair; restore both files or remove both and rerun setup.")
if not private.exists():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with os.fdopen(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    public.chmod(0o644)
    print("Generated development signing keys in .local/keys (gitignored).")
else:
    print("Using existing development keys.")
