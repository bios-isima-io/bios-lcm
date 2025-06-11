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

from lib.bios_container_common import (
    bios_candidates,
    bios_status,
    diagnose_and_repair_bios_node,
    report_bios_status,
    start_bios_container,
    stop_bios_container,
    stop_broken_bios,
)
from lib.common import execute_wrapped, get_name_and_ip, initialize_lcm, run_remote
from lib.log import Log
from packaging import version


def _print_help_and_exit():
    print(
        f"""

Usage:
    {sys.argv[0]} restore [verbose]
            : restore a bi(OS) cluster to a previous version, as specified in the cluster config.
              The status command may be used to check the restore versions available.

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


def restore_bios(config):
    """Restores all storage nodes of the bios cluster to the version specified in
        the config.

    Args:
        config (dict): The cluster configuration.
    """
    storage_nodes = config["roles"]["storage"]

    # Order the nodes to be restored as per the user config.
    node_order = config["restore_order"]
    restore_nodes = sorted(storage_nodes, key=lambda node: node_order.index(node["sub_role"]))

    eligible_nodes = []
    current_versions = {}
    restore_version = config["bios_version"]
    allow_partial_restore = config["allow_partial_restore"]

    for host in restore_nodes:
        current_version = bios_status(host, config)
        candidate_versions = bios_candidates(host, config)

        if current_version == "None":
            Log.info(f"No previous version of bios found running on host {get_name_and_ip(host)}")
        elif version.parse(restore_version) == version.parse(current_version):
            Log.info(
                f"Node {get_name_and_ip(host)} already running bios version"
                f" {current_version}. Nothing to do."
            )

            if allow_partial_restore:
                Log.info(f"Skipping the node.")
            continue

        if restore_version not in candidate_versions:
            Log.error(
                f"Restore: A usable installation of the specified bios version {restore_version}"
                f" not found on node {get_name_and_ip(host)}."
            )
            if allow_partial_restore:
                Log.info(f"Skipping the node.")
            continue

        eligible_nodes.append(host)
        current_versions[host["name"]] = current_version

    if not allow_partial_restore and eligible_nodes != restore_nodes:
        Log.error(
            f"Restore: All nodes do not have the requested version available, and property"
            f" 'allow_partial_restore' is not set. Aborting!"
        )
        return

    for host in eligible_nodes:
        Log.info(f"Restoring bios to version {restore_version} on host {get_name_and_ip(host)}")
        restore_bios_node(host, config, restore_version, current_versions[host["name"]])


def restore_bios_node(host, config, bios_version, current_version):
    """Restores bios on the host to the version specified in the cluster config.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string): The version of bios to restore to.
        current_version (string): The current version of bios running on the node.
    """
    if current_version != "None":
        stopped_container = stop_bios_container(host, config)
    try:
        diagnose_and_repair_bios_node(host, config, bios_version=bios_version)
    except Exception as exception:
        Log.error(
            f"Error while performing restore on node {get_name_and_ip(host)}."
            f" Got exception: {str(exception)}"
            f" Performing a rollback to the running version"
        )

        stop_broken_bios(host, "restore", config)

        if current_version == "None":
            Log.error(f"There was no running version of bios. Quitting.")
            return

        run_remote(host, f"docker rename {stopped_container} bios")
        start_bios_container(host, config)


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
        elif first_arg == "restore":
            restore_bios(config)
            Log.marker("Completed restore of the bi(OS) cluster")
        elif first_arg == "status":
            report_bios_status(config)
        else:
            _print_help_and_exit()


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
