#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2025, Arpan Mandal <me@arpanrec.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import base64

__metaclass__ = type  # pylint: disable=invalid-name

import argparse
import getpass
import json
import os
import subprocess  # nosec B404
import sys
from typing import Dict, List, Optional

from ansible.config.manager import (  # type: ignore[import-untyped]
    ConfigManager,
    get_ini_config_value,
)

KEYNAME_UNKNOWN_RC = 2


def __build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Get a vault password from Bitwarden CLI"
    )

    parser.add_argument(
        "--bw-item",
        action="store",
        default=None,
        dest="bw_item_name",
        help="name or ID of the Bitwarden item to use for storing the vault password, default is 'ANSIBLE_VAULT_PASS'",
    )

    parser.add_argument(
        "--vault-id",
        action="store",
        default=None,
        dest="vault_id",
        help="name of custom field in the Bitwarden item to use for storing the vault password, default is 'default'",
    )
    parser.add_argument(
        "--set",
        action="store_true",
        default=False,
        dest="set_password",
        help="set the password instead of getting it",
    )

    return parser


def __bw_exec(
    cmd: List[str],
    ret_encoding: str = "UTF-8",
    env_vars: Optional[Dict[str, str]] = None,
    is_raw: bool = True,
    input_val: Optional[str] = None,
) -> str:
    """
    Executes a Bitwarden CLI command and returns the output as a string.
    """
    cmd = ["bw"] + cmd

    if is_raw:
        cmd.append("--raw")

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)

    command_out = subprocess.run(
        cmd,
        capture_output=True,
        check=False,
        encoding=ret_encoding,
        env=cli_env_vars,
        timeout=10,
        shell=False,
        input=input_val,
        text=True if input_val is not None else None,
    )  # nosec B603
    if command_out.returncode != 0:
        sys.stderr.write(f"Error executing command: {' '.join(cmd)}\n")
        sys.stderr.write(f"Return code: {command_out.returncode}\n")
        sys.stderr.write(f"Error output: {command_out.stderr}\n")
        sys.exit(command_out.returncode)
    return command_out.stdout


def main():
    vault_id = "default"
    bw_item_name = "ANSIBLE_VAULT_PASS"

    # Try to load values from config if one exists
    config = ConfigManager()
    if config._config_file:  # pylint: disable=protected-access

        vault_id = (
            get_ini_config_value(
                # pylint: disable=protected-access
                config._parsers[config._config_file],
                {"section": "vault", "key": "bw_item_field"},
            )
            or vault_id
        )

        bw_item_name = (
            get_ini_config_value(
                # pylint: disable=protected-access
                config._parsers[config._config_file],
                {"section": "vault", "key": "bw_item"},
            )
            or bw_item_name
        )

    arg_parser = __build_arg_parser()
    args = arg_parser.parse_args()

    vault_id = args.vault_id or vault_id

    __bw_exec(["sync"])
    bw_item = __bw_exec(["get", "item", bw_item_name])
    bw_item_dict = json.loads(bw_item)
    bw_item_id = str(bw_item_dict.get("id"))
    bw_fields = list(bw_item_dict.get("fields", []))

    if args.set_password:
        intro = f"Setting Bitwarden item {bw_item_name} using field name: {vault_id}\n"
        sys.stdout.write(intro)
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            sys.stderr.write("Passwords do not match\n")
            sys.exit(1)

        field_exists = False
        for field in bw_fields:
            if field.get("name") == vault_id:
                field["value"] = password
                field_exists = True
                break

        if not field_exists:
            new_field = {
                "name": vault_id,
                "value": password,
                "type": 1,
                "linkedId": None,
            }
            bw_fields.append(new_field)

        bw_item_dict["fields"] = bw_fields
        updated_item_json = json.dumps(bw_item_dict)
        bw_base64 = base64.b64encode(updated_item_json.encode("utf-8")).decode("utf-8")
        __bw_exec(
            ["edit", "item", bw_item_id],
            input_val=bw_base64,
        )
    else:
        secret = None

        for field in bw_fields:
            if field.get("name") == vault_id:
                secret = field.get("value")
                break

        if secret is None:
            sys.stderr.write(
                "ansible vault bitwarden-client could not find,"
                f' field="{vault_id}" in Bitwarden item "{bw_item_name}"\n'
            )
            sys.exit(KEYNAME_UNKNOWN_RC)

        sys.stdout.write(f"{secret}\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
