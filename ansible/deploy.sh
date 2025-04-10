#!/usr/bin/env bash
set -euo pipefail

log_message() {
    printf "\n\n================================================================================\n %s \
Setup Cryptpass: \
%s\n--------------------------------------------------------------------------------\n\n" "$(date)" "$*"
}

log_message "Installing required collections and roles"
uv pip install -e .
uv run ansible-galaxy collection install community.general
uv run ansible-galaxy collection install community.docker
uv run ansible-galaxy role install geerlingguy.docker
uv run ansible-playbook ansible/playbook.yml
