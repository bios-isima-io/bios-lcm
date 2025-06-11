#!/usr/bin/env python3
#
# Copyright (C) 2025 Isima, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys

import bios
from lib.bios_apps import configure_apps, configure_load, configure_sql
from lib.common import (
    execute_wrapped,
    get_cluster_dns_name_port,
    initialize_lcm,
    load_yaml_file,
    replace_line_re,
    run_local,
)
from lib.common_with_bios import create_bios_session_system
from lib.constants import LOCAL_RES_PATH_BASE
from lib.docker_instance import retabulate_version_numbers
from lib.log import Log


def augment_bios(config, augment_file):
    basename = os.path.basename(augment_file)
    run_local(f"cp --no-preserve=mode {augment_file} {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/{basename}"
    replace_line_re("CLUSTER_DNS_NAME", get_cluster_dns_name_port(config), file)
    augment = load_yaml_file(file)

    tenant_name = augment["tenant_name"]

    if "users" in augment:
        session = create_bios_session_system(config)
        for entry in augment["users"]:
            Log.info(f"Creating user {entry['user']}")
            user = bios.User(
                entry["user"],
                entry["full_name"],
                tenant_name,
                entry["password"],
                entry["roles"],
            )
            session.create_user(user)

    if "bios-integrations" in augment:
        configure_apps(config, augment)
    if "bios-sql" in augment:
        configure_sql(config, augment)
    if "load" in augment:
        configure_load(config, augment)


def _print_help_and_exit(exit_code):
    print(
        f"""

Usage:
    {sys.argv[0]} <config yaml file> [verbose]
            : Add new components to an existing bi(OS) cluster.

    config yaml file: path to the yaml file containing the configuration
                        for the new additions. Format is the same as that of tenant.yaml.
    verbose: optionally print verbose logs
    """
    )
    sys.exit(exit_code)


def main():
    if len(sys.argv) < 2:
        _print_help_and_exit(1)
    else:
        first_arg = sys.argv[1]
        if first_arg in ["--help", "-h"]:
            _print_help_and_exit(0)

    if len(sys.argv) >= 3 and sys.argv[2] == "verbose":
        Log.set_verbose_output(True)

    config = initialize_lcm()
    retabulate_version_numbers(config)

    augment_file = sys.argv[1]

    augment_bios(config, augment_file)
    Log.marker("Completed augmenting the cluster.")


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
