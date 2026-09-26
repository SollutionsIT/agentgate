#!/usr/bin/env bash
# Codespaces can retain an old iptables-legacy DROP policy after Docker switches to nft.
# Permit only same-bridge traffic for this project's fixed, private bridge names.
# Docker's current nft isolation rules still apply; no global policy is changed.
set -euo pipefail
[[ "${CODESPACES:-}" == "true" ]] || exit 0
command -v iptables-legacy >/dev/null || exit 0
iptables --version | grep -q nf_tables || exit 0
if ! sudo -n iptables-legacy -S FORWARD 2>/dev/null | grep -q -- '-P FORWARD DROP'; then
  exit 0
fi
for bridge in ag-control ag-weather ag-finance ag-edge; do
  rule=(-i "$bridge" -o "$bridge" -m comment --comment agentgate-codespace -j ACCEPT)
  if [[ "${1:-}" == "--remove" ]]; then
    if sudo -n iptables-legacy -C FORWARD "${rule[@]}" 2>/dev/null; then
      sudo -n iptables-legacy -D FORWARD "${rule[@]}"
    fi
  elif ! sudo -n iptables-legacy -C FORWARD "${rule[@]}" 2>/dev/null; then
    sudo -n iptables-legacy -I FORWARD 1 "${rule[@]}"
    echo "Enabled Codespace same-bridge forwarding for $bridge (legacy/nft compatibility)."
  fi
done
