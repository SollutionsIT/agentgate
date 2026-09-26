"""Check built distributions for runtime artifacts and actual private-key blocks."""

import re
import tarfile
import zipfile
from pathlib import Path

forbidden = {".local", ".venv", ".bootstrap", "__pycache__", ".pytest_cache", ".git"}
private_key = re.compile(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n")
artifacts = [*Path("dist").glob("*.whl"), *Path("dist").glob("*.tar.gz")]
if len(artifacts) != 2:
    raise SystemExit("Expected one wheel and one source distribution")
for artifact in artifacts:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
    else:
        with tarfile.open(artifact) as archive:
            entries = {}
            for member in archive.getmembers():
                if member.isfile():
                    file = archive.extractfile(member)
                    assert file is not None
                    entries[member.name] = file.read()
    for name, content in entries.items():
        assert not forbidden.intersection(Path(name).parts), f"Runtime artifact: {name}"
        assert not name.endswith((".pem", ".key", ".pyc", ".log")), f"Unexpected artifact: {name}"
        assert not private_key.search(content), f"Private key in {name}"
    assert any(name.endswith("LICENSE") for name in entries), "Missing license"
    print(f"PASS: {artifact.name}: license included; no runtime state or private keys")
