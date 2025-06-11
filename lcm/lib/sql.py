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
"""Module that manages biOS sql"""

import os
import time

from lib.bios_container_common import retrieve_container_name, retrieve_current_version
from lib.common import execute_on_hosts, get_name_and_ip, run_remote
from lib.install_upgrade_common import (
    build_docker_create_command,
    check_image_spec,
    check_installed_containers,
    determine_target_tenants,
    obtain_docker_image,
)
from lib.log import Log


def upgrade_sql(config: dict, options: dict):
    """Upgrades bios maintenance container"""
    list_only = options.get("list_only")

    base_container_name = "bios-sql"

    compute_nodes = config["roles"]["compute"]
    installed_tenants = check_installed_containers(compute_nodes, base_container_name)
    if list_only:
        Log.info("Installed tenants:")
        for tenant, nodes in installed_tenants.items():
            Log.info(f"  {tenant}: {list(nodes)}")
        return

    target_tenants = determine_target_tenants(options, installed_tenants)
    if not target_tenants:
        Log.warn("Nothing to upgrade, exiting")
        return

    upgrade_core(
        config, options, compute_nodes, target_tenants, base_container_name, installed_tenants
    )


def upgrade_core(
    config, options, compute_nodes, target_tenants, base_container_name, installed_tenants
):
    """The main part of the integration upgrade"""

    image_file, config["image_name"], target_version = check_image_spec(
        options, base_container_name
    )
    config["image_file"] = image_file

    execute_on_hosts(obtain_docker_image, "Obtaining new docker images", compute_nodes, config)

    if image_file:
        # determine the version number by the image tag
        image_full_name = config.get("image_full_name")
        target_version = image_full_name.split(":")[1]
    config["target_version"] = target_version

    for tenant in target_tenants:
        Log.info(f"Upgrading bios-integrations for tenant {tenant}")
        container_name = f"{base_container_name}-{tenant}"
        for host in compute_nodes:
            node_string = get_name_and_ip(host)
            Log.info(f"  host={node_string}")

            container_properties = installed_tenants[tenant].get(host["name"])
            if not container_properties:
                Log.info(f"    {container_name} is not installed on host {node_string}. Skipping")
                continue

            # figure out the log file path to monitor
            log_path = None
            for mount in container_properties["Mounts"]:
                if mount["Type"] == "bind" and mount["Destination"] == "/var/log/apps":
                    log_path = mount["Source"]
                    break
            if log_path:
                log_path += "/trino/trino.log"
            # figure out TLS cert file path if any
            cert_file_path = None
            for env in container_properties["Config"]["Env"]:
                if env.startswith("SSL_CERT_FILE="):
                    cert_file_path = env[14:]
                    break
            backup_cert_file_path = (
                f"/tmp/{os.path.basename(cert_file_path)}" if cert_file_path else None
            )

            command, image_name, image_version = build_docker_create_command(
                config,
                container_name,
                container_properties,
                env_vars=[
                    "APPLICATIONS",
                    "BIOS_ENDPOINT",
                    "BIOS_TENANT",
                    "BIOS_USER",
                    "BIOS_PASSWORD",
                    "SSL_CERT_FILE",
                ],
            )

            current_version = retrieve_current_version(container_properties)
            if current_version == target_version:
                Log.info(
                    f"    Version {target_version} is installed on {node_string} already, skipping"
                )
                continue

            current_container_name = retrieve_container_name(container_properties)
            if cert_file_path:
                # take backup of TLS cert file
                run_remote(
                    host,
                    f"docker cp {current_container_name}:{cert_file_path} {backup_cert_file_path}",
                )
            run_remote(
                host,
                f"docker cp {current_container_name}:/opt/bios/server.cert.pem /tmp",
            )
            if current_container_name == container_name:
                renamed = f"{container_name}_{current_version}"
                run_remote(host, f"docker rename {current_container_name} {renamed}")
                current_container_name = renamed
            else:
                Log.debug(
                    f"Skipping to rename container {current_container_name} on {node_string}"
                )
                renamed = None

            try:
                run_remote(host, command)
                if cert_file_path:
                    run_remote(
                        host,
                        f"docker cp {backup_cert_file_path} {container_name}:{cert_file_path}",
                    )
                run_remote(host, f"docker cp /tmp/server.cert.pem {container_name}:/opt/bios/")
            except RuntimeError as error:
                if renamed:
                    Log.error(
                        f"Failed to create new bios container from image"
                        f" {image_name}:{image_version} on host {get_name_and_ip(host)}."
                        f"\nEncountered exception: {str(error)}"
                        f"\nRolling back to version: {current_version}"
                    )
                    run_remote(host, f"docker start {renamed}")
                    run_remote(host, f"docker rename {renamed} {container_name}")
                    # abort here
                    return

            if container_properties.get("State", {}).get("Running", False):
                Log.debug(f"Stopping {current_container_name} container on: {node_string}")
                run_remote(host, f"docker stop {current_container_name}")
            else:
                Log.debug(
                    f"Container {current_container_name} is stopped already on: {node_string}"
                )

            # remember the log file position
            if log_path:
                result = run_remote(host, f"wc -l {log_path} | awk '{{print $1}}'")
                initial_log_lines = int(result.stdout)
            else:
                initial_log_lines = None

            try:
                Log.info(f"    Starting the new container {container_name} on: {node_string}")
                run_remote(host, f"docker start {container_name}")
                Log.info(
                    f"    New {container_name} version {target_version} has started."
                    " Sleeping for 20 seconds to wait for things settled"
                )
                time.sleep(20)
                if not log_path:
                    Log.debug("Log path could not be resolved, skip checking the log")
                result = run_remote(host, f"wc -l {log_path} | awk '{{print $1}}'")
                current_log_lines = int(result.stdout)
                num_lines = current_log_lines - initial_log_lines
                result = run_remote(host, f"tail -n {num_lines} {log_path} | grep ERROR | wc -l")
                if int(result.stdout) > 0:
                    raise RuntimeError(f"{int(result.stdout)} errors are found after upgrading")
            except RuntimeError as error:
                if renamed:
                    Log.error(
                        f"Failed to upgrade bios to version {image_version}"
                        f" on host {get_name_and_ip(host)}."
                        f"\nEncountered exception: {str(error)}"
                        f"\nRolling back to version: {current_version}"
                    )

                    try:
                        run_remote(host, f"docker stop {container_name}")
                    except Exception as err:
                        Log.warn(f"    Error in stopping {container_name} but continue: {err}")
                    run_remote(host, f"docker start {renamed}")
                    run_remote(
                        host,
                        f"docker rename {container_name} {container_name}_fail_{target_version}",
                    )
                    run_remote(host, f"docker rename {renamed} {container_name}")
                Log.error("Upgrading aborted")
                return
            Log.info(
                f"    Upgraded {container_name} from version {current_version}"
                f" to version {image_version} on: {node_string}"
            )
            run_remote(host, f"rm -f {backup_cert_file_path}, /tmp/server.cert.pem")
