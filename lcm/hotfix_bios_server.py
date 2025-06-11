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
from functools import partial
from urllib.parse import urlparse

from lib.common import (
    execute_on_hosts,
    execute_wrapped,
    get_name_and_ip,
    initialize_lcm,
    is_valid_url,
    put_file,
    run_local,
    run_remote,
    run_sudo_remote,
    wait_for_bios_up,
)
from lib.docker_instance import retabulate_version_numbers
from lib.log import Log


def _print_help_and_exit():
    print(
        f"""

Usage:
    {sys.argv[0]} <bios war file path / URL> [thisIsNotAProductionCluster] [parallel] [verbose]
            : Hotfix bios server on the bi(OS) cluster.

    bios war file path / URL: This can be either a valid local path to the war file to be deployed,
                              or a valid url (http/https/ftp) which can used to download the file
                              using wget.

    thisIsNotAProductionCluster: enables unsafe options/operations; do not use this switch
                on production clusters!

    parallel: If specified, all servers are updated in parallel, which results in downtime
                for the cluster. Requires thisIsNotAProductionCluster.

    verbose: optionally print verbose logs
    """
    )
    sys.exit(1)


def apply_patch(new_file, index, host, config):
    """Deploys the copied war file after undeploying the previous one. Waits for the server to
    come up after.

    Args:
        new_file (string): Name of the new war file already copied to the docker container.
        index (iint): Not used.
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster config as provided throught yaml.
    """
    del index
    # TODO get old file.
    old_file = ""

    Log.debug(f"Un-deploying {old_file} on {get_name_and_ip(host)}")
    run_remote(host, f"docker exec bios undeploy.sh {old_file}")
    run_remote(host, f"docker exec bios deploy.sh /opt/bios/{new_file}")
    Log.debug(f"Waiting for deployment to finish fully on {get_name_and_ip(host)}")
    wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")

    Log.debug(f"Restarting bios container on {get_name_and_ip(host)}")
    run_remote(host, "docker restart bios")
    Log.debug(f"Waiting for bios container to restart fully on {get_name_and_ip(host)}")
    wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")
    Log.debug(f"Completed hot-fixing on {get_name_and_ip(host)}")


def distribute_war_file(index, host, war_file_path):
    """Copies the war file to be applied to the node and then inside the bios docker container
    running on it. Also clears off any previous files on the node.

    Args:
        index (int): Not used.
        host (LCM host object): The host on which to operate on.
        war_file_path (string): The path on the LC machine from where the war file is to be copied.
    """
    del index
    new_file = os.path.basename(war_file_path)
    run_sudo_remote(host, "rm -f /tmp/*.war")
    put_file(host, war_file_path, "/tmp")
    run_remote(host, f"docker cp /tmp/{new_file} bios:/opt/bios/")


def hotfix_bios_server(config, bios_war_uri, parallel):
    """Hotfixes the cluster by deploying the provided war file on it.

    Args:
        config (dict): The cluster config as provided throught yaml.
        bios_war_uri (string): The path or url to fetch the war file from.
        parallel (bool): Whether to apply the patch on all storage nodes in parallel or not.
    """
    Log.info(f"Hot-fixing bios server using war file {bios_war_uri}")
    # Hotfix on each storage host.
    storage_nodes = config["roles"]["storage"]

    if is_valid_url(bios_war_uri):
        new_file = os.path.basename(urlparse(bios_war_uri).path)
        local_file_path = f"/tmp/{new_file}"
        Log.debug(f"Downloading war file {bios_war_uri}")
        run_local(f"wget {bios_war_uri} -O {local_file_path}")
    else:
        local_file_path = bios_war_uri
        new_file = os.path.basename(bios_war_uri)

    # Parallel distribution of the patch file.
    execute_on_hosts(
        distribute_war_file, "Distributing the war file", storage_nodes, local_file_path
    )

    # Apply patch serially
    execute_on_hosts(
        partial(apply_patch, new_file), "Applying the patch", storage_nodes, config, parallel
    )


def main():
    """The driver function.

    Raises:
        Exception: In case an invalid option is provided.
    """
    if len(sys.argv) < 2:
        _print_help_and_exit()
    else:
        bios_war_uri = sys.argv[1]
        is_production_cluster = True
        parallel = False
        args_used = 2

        if len(sys.argv) > args_used and sys.argv[args_used] == "thisIsNotAProductionCluster":
            is_production_cluster = False
            args_used += 1

        if len(sys.argv) > args_used and sys.argv[args_used] == "parallel":
            if is_production_cluster:
                raise Exception(f"parallel option is not meant for use on production clusters!")
            parallel = True
            args_used += 1

        if len(sys.argv) > args_used and sys.argv[args_used] == "verbose":
            Log.set_verbose_output(True)

        config = initialize_lcm()
        retabulate_version_numbers(config)

        hotfix_bios_server(config, bios_war_uri, parallel)
        Log.marker("Completed hot-fixing bios server!")


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
