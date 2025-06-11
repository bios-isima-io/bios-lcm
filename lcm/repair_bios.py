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

import sys

from lib.bios_container_common import diagnose_and_repair_bios_node, report_bios_status
from lib.common import execute_wrapped, get_name_and_ip, initialize_lcm
from lib.log import Log


def _print_help_and_exit():
    print(
        f"""

Usage:
    {sys.argv[0]} repair [verbose]
            : diagnose and repair a bi(OS) cluster by detecting failures and setting up a bios
             container of the most recent stable version available on the node.

    {sys.argv[0]} status [verbose]
            : report the installation status of a bi(OS) cluster listing the current installation
              as well as the list of available bios versions on it.

    {sys.argv[0]} validate [verbose]
            : do not install; only validate the inputs and hosts.

    verbose: optionally print verbose logs

Ensure the following files are updated in /isima/lcm/env directory:
    * hosts.yaml
    * cluster_config.yaml
    * web.cert.pem
    * web.key.pem
    * tenant.yaml

For detailed instructions, see /isima/lcm/lcm/README.md
    """
    )
    sys.exit(1)


def repair_bios(config):
    """Diagnoses and repairs all storage nodes in a bios cluster.

    Args:
        config (dict): The cluster configuration.
    """
    storage_nodes = config["roles"]["storage"]

    # Make sure the server addresses in the database are also updated.
    preserved_property_value = config["rewrite_bios_addresses"]
    config["rewrite_bios_addresses"] = True

    # Order the nodes to be repaired as per the user config.
    node_order = config["repair_order"]
    repair_nodes = sorted(storage_nodes, key=lambda node: node_order.index(node["sub_role"]))

    for host in repair_nodes:
        Log.info(f"Diagnosing and repairing node {get_name_and_ip(host)}")
        diagnose_and_repair_bios_node(host, config)

    # Set back to specified behaviour.
    config["rewrite_bios_addresses"] = preserved_property_value


def main():
    if len(sys.argv) < 2:
        _print_help_and_exit()
    else:
        if len(sys.argv) >= 3 and sys.argv[2] == "verbose":
            Log.set_verbose_output(True)

        config = initialize_lcm()

        first_arg = sys.argv[1]
        if first_arg == "validate":
            Log.marker("Completed validating connections to all hosts!")
        elif first_arg == "repair":
            repair_bios(config)
            Log.marker("Completed repairing the bi(OS) cluster")
        elif first_arg == "status":
            report_bios_status(config)
        else:
            _print_help_and_exit()


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
