#!/usr/bin/env bash
set -euo pipefail

bw sync --quiet
bw_item=$(bw get item ANSIBLE_VAULT_PASS --raw)

echo "${bw_item}" | jq '.fields[] | select(.name == "easyiac_cryptpass").value' -c -r
