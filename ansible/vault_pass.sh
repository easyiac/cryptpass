#!/usr/bin/env bash
set -euo pipefail

bw sync --quiet
bw_item=$(bw get item cryptpass --raw)

echo "${bw_item}" | jq '.fields[] | select(.name == "ANSIBLE_VAULT_PASS").value' -c -r
