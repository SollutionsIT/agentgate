"""Remove only known, generated development artifacts inside this repository."""

import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for name in (".local", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist"):
    path = root / name
    if path.exists() and not path.is_symlink():
        shutil.rmtree(path)
for folder in ("src", "tests", "scripts", "examples"):
    for path in (root / folder).rglob("__pycache__"):
        shutil.rmtree(path)
