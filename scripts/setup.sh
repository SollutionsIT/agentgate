#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .local/bin .local/keys
if [[ ! -x .bootstrap/bin/uv ]]; then
  python3 -m venv .bootstrap
  .bootstrap/bin/python -m pip install --disable-pip-version-check 'uv==0.12.19'
fi
export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.local/uv-cache}"
.bootstrap/bin/uv sync --frozen
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) arch=amd64; digest=5eef70644868bb04d0556bcc795ee42f2ab379e73f51d1bfa30f83e1305bc9b9 ;;
  Linux-aarch64) arch=arm64; digest=0ec34027c15b4d969c21d01ed570fe14fbebd508a08157043ab09f9a0dccbee6 ;;
  *) echo 'Use a Linux Codespace (amd64 or arm64) for the supported setup.' >&2; exit 1 ;;
esac
if ! echo "$digest  .local/bin/opa" | sha256sum --check --status 2>/dev/null; then
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    "https://github.com/open-policy-agent/opa/releases/download/v1.21.0/opa_linux_${arch}_static" \
    --output .local/bin/opa.download
  echo "$digest  .local/bin/opa.download" | sha256sum --check
  mv .local/bin/opa.download .local/bin/opa
  chmod 755 .local/bin/opa
fi
.venv/bin/python scripts/keys.py
