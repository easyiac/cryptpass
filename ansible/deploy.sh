#!/usr/bin/env bash
set -euo pipefail

log_message() {
    printf "\n\n================================================================================\n %s \
Setup Cryptpass: \
%s\n--------------------------------------------------------------------------------\n\n" "$(date)" "$*"
}

log_message "Installing required collections and roles"
poetry install
poetry run ansible-galaxy collection install community.general
poetry run ansible-galaxy collection install community.docker
poetry run ansible-galaxy role install geerlingguy.docker
poetry run ansible-playbook ansible/playbook.yml
