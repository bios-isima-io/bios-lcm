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
"""Module for upgrading bios components"""

import datetime
import re
import sys
import time
from typing import Any, Callable, Dict, List, Tuple, Union

from lib.bios_container_common import (
    check_container,
    retrieve_binds,
    retrieve_container_name,
    retrieve_cpuset_cpus,
    retrieve_current_version,
    retrieve_extra_hosts,
    retrieve_memory,
    stop_broken_bios,
    wait_for_bios_up,
)
from lib.cert_renewer import (
    backup_certs_and_stores,
    copy_new_certs_and_stores_to_targets,
    fetch_certs_and_stores,
    replace_certs_and_restart_lb_nodes,
    update_trust_stores,
)
from lib.common import (
    download_file,
    execute_on_hosts,
    execute_wrapped,
    get_container_resources_directory,
    get_name_and_ip,
    get_resources_path,
    initialize_lcm,
    load_yaml_file,
    parse_string_table,
    put_file,
    run_local,
    run_remote,
)
from lib.constants import (
    CONTAINER_T_BIOS,
    CONTAINER_T_STORAGE,
    CREDS_FILE,
    UPGRADE_CONFIGS_PATH,
    UPGRADE_RESOURCES_BASE_PATH,
)
from lib.docker_instance import get_docker_instance
from lib.install_upgrade_common import (
    build_docker_create_command,
    install_dependencies,
    reopen_connections,
    setup_connect_aliases,
    wait_for_db_cluster_formation,
)
from lib.integrations import upgrade_integrations
from lib.log import Log
from lib.maintainer import upgrade_maintainer
from lib.sql import upgrade_sql
from packaging.version import Version


def upgrade_bios(config, options):
    """Upgrade the bios containers on the storage nodes of the cluster.

    Args:
        config (dict): The cluster configuration.

    Raises:
        Exception: In case any error is encountered while performing the upgrade.
    """
    upgrade_containers_in_storage_nodes(
        config,
        options,
        CONTAINER_T_BIOS,
        build_bios_create_command,
        lambda host, conf: wait_for_bios_up(None, f"https://{host['ip']}:{conf['https_port']}"),
    )


def build_bios_create_command(host: dict, config: dict) -> Tuple[str, str, str]:
    """Makes a command string to create the next version of bios container"""
    container_properties = host["container_properties"]

    components = ["docker create --name bios --network host --restart unless-stopped"]

    for extra_host in retrieve_extra_hosts(container_properties) or []:
        components.append(f"--add-host {extra_host}")

    for bind in retrieve_binds(container_properties) or []:
        components.append(f"-v {bind}")

    memory = retrieve_memory(container_properties)
    if memory:
        components.append(f"--memory={memory}")

    cpuset = retrieve_cpuset_cpus(container_properties)
    if cpuset:
        components.append(f"--cpuset-cpus={cpuset}")

    if config.get("image_full_name"):
        elements = config["image_full_name"].split(":")
        image_name = elements[0]
        image_version = elements[1]
    else:
        image_name = config.get("image_name", "bios")
        image_version = config["target_version"]
    components.append(f"{image_name}:{image_version}")

    command = " ".join(components)
    return command, image_name, image_version


def apply_upgrade_config_patch(host, upgrade_config_filename, options):
    """Apply an upgrade config to a host options file.

    Args:
        host (LCM host object): The host on which to operate on.
        upgrade_config_filename (string): The file containing the config patch to be applied.
        options (dict): The options to be applied for the node.
    """
    Log.info(f"Applying upgrade config {upgrade_config_filename} for host {get_name_and_ip(host)}")

    upgrade_config = load_yaml_file(f"{UPGRADE_CONFIGS_PATH}/{upgrade_config_filename}")
    Log.debug(f"upgrade_config being applied : {upgrade_config}")

    properties_to_set = upgrade_config["properties_to_set"]
    properties_to_unset = upgrade_config["properties_to_unset"]
    properties_to_rename = upgrade_config["properties_to_rename"]

    for key in properties_to_set.keys():
        if key in options.keys():
            Log.debug(f"set old property {key} to {properties_to_set[key]}")
        else:
            Log.debug(f"set new property {key} to {properties_to_set[key]}")
        options[key] = properties_to_set[key]

    for key in properties_to_unset:
        options.pop(key, None)
        Log.debug(f"property {key} unset")

    for key in properties_to_rename.keys():
        value = options.get(key)
        if value:
            options.pop(key)
            options[properties_to_rename[key]] = value
            Log.debug(
                f"property {key} renamed to {properties_to_rename[key]}."
                f" Value retained to be {value}"
            )
        else:
            Log.info(
                f"Config key {key} to be renamed does not exist in config for host "
                f"{get_name_and_ip(host)}, skipped."
            )


def build_storage_create_command(host: dict, config: dict) -> Tuple[str, str, str]:
    """Makes a command string to create the next version of bios-storage container"""
    container_name = config["container_name"][CONTAINER_T_STORAGE]
    container_properties = host["container_properties"]
    return build_docker_create_command(
        config,
        container_name,
        container_properties,
        env_vars=[
            "DB_JVM_SERVER_OPTIONS",
            "DB_BROADCAST_RPC_ADDRESS",
            "DB_KEYSTORE",
            "DB_ENV",
            "DB_RACKDC_PROPERTIES",
            "DB_ENDPOINT_SNITCH",
            "JAVA_TOOL_OPTIONS",
            "DB_YAML",
            "DB_TRUSTSTORE",
            "DB_JVM_CLIENTS_OPTIONS",
            "DB_CLUSTER_NAME",
            "DB_BROADCAST_ADDRESS",
            "DB_JVM11_SERVER_OPTIONS",
            "BIOS_SEEDS",
            "DB_VER",
            "DB_HOME",
        ],
        extra_params=[
            "--ulimit nofile=1000000:1000000",
            "--ulimit nproc=32768",
            "--ulimit memlock=-1:-1",
        ],
    )


def copy_storage_resources(host, config):
    """Copies resources necessary to the storage container"""
    bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    resources_dir = get_resources_path(config, "db_resources_dir")
    Log.debug(f"Copying necessary resources in the container {bios_storage}")
    run_remote(host, f"docker cp {resources_dir}/jmxremote.password {bios_storage}:/opt/db/conf/")
    run_remote(host, f"docker cp {resources_dir}/cqlshrc {bios_storage}:/root/.cassandra/")


def wait_for_storage_node_up(host, config):
    """Method to wait for a bios-storage node being up"""
    num_nodes = len(config["roles"]["storage"])
    Log.info(
        f"Waiting for the storage node coming up on {host['name']}."
        " This waits up to 15 minutes. Please be patient."
    )
    log_file_name = (
        f"{config['log_base_path']}/{config['db_log_dir']}/system.log on {host['name']}"
    )
    Log.info(f"You may also want to check {log_file_name}")
    wait_for_db_cluster_formation(host, num_nodes, config, 15 * 60)


def upgrade_storage(config, options):
    """Upgrade the bios-storage containers on the storage nodes of the cluster.

    Args:
        config (dict): The cluster configuration.

    Raises:
        Exception: In case any error is encountered while performing the upgrade.
    """

    upgrade_containers_in_storage_nodes(
        config,
        options,
        CONTAINER_T_STORAGE,
        build_storage_create_command,
        wait_for_storage_node_up,
        run_post_create=copy_storage_resources,
    )


def upgrade_containers_in_storage_nodes(
    config: dict,
    options: dict,
    container_type: str,
    build_create_command: Callable[[dict, dict], Tuple[str, str, str]],
    wait_for_container_ready: Callable[[dict, dict], None],
    run_post_create: Callable[[dict, dict], None] = None,
):
    """Generic method for upgrading containers in storage nodes"""
    # Check target version
    image_file = options.get("image_file")
    if image_file:
        config["image_file"] = image_file
    else:
        target_version = options.get("version")
        if not target_version:
            raise RuntimeError(
                "--image_file or --version options must be specified to upgrade biOS."
            )
        config["image_name"] = options.get("image_name", "bios-storage")

    storage_nodes = config["roles"]["storage"]

    # Pull the new image on all nodes, in parallel.
    execute_on_hosts(
        pull_bios_image, f"Obtaining new {container_type} image", storage_nodes, config
    )

    # Retrieve the target version in case of uploading the new image
    if image_file:
        target_version = config.get("image_full_name").split(":")[1]

    upgrade_nodes = []

    # For each node, verify container health and check if new version requested.
    for storage_node in storage_nodes:
        _, container_properties = check_container(storage_node, config, container_type)
        current_version = retrieve_current_version(container_properties)
        storage_node["current_version"] = current_version
        storage_node["container_properties"] = container_properties

        # If the requested version already installed, make sure it is healthy.
        if target_version == current_version:
            Log.info(
                f"The node has {container_type} version {target_version} that is the"
                f" same as the version to upgrade."
                f" Skipping {container_type} update for host: {get_name_and_ip(storage_node)}."
            )
            continue

        upgrade_nodes.append(storage_node)

    config["target_version"] = target_version
    if not upgrade_nodes:
        Log.info("All nodes already running the target version, skipping their upgrades.")
        return

    config["num_nodes_to_upgrade"] = len(upgrade_nodes)

    # Order the nodes to be upgraded as per the user config.
    node_order = config["upgrade_order"]
    upgrade_nodes = sorted(upgrade_nodes, key=lambda node: node_order.index(node["sub_role"]))

    for storage_node in upgrade_nodes:
        Log.info(
            f"*** Upgrading {container_type} container for host: {get_name_and_ip(storage_node)}"
        )
        upgrade_container_in_storage_node(
            storage_node,
            config,
            container_type,
            build_create_command,
            wait_for_container_ready,
            run_post_create,
        )


def upgrade_container_in_storage_node(
    host: dict,
    config: dict,
    container_type: str,
    build_create_command: Callable[[dict, dict], Tuple[str, str, str]],
    wait_for_container_ready: Callable[[dict, dict], None],
    run_post_create: Callable[[dict, dict], None] = None,
):
    """Upgrade a container on the specified storage node.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        container_type (str): Container type.
        build_create_command (Callable): Function to build the docker create command.
        wait_for_container_ready (Callable): Function to wait for the container being ready.

    Raises:
        Exception: In case an unexpected error is encountered in the process.

    Returns:
        bool: Success or Failure.
    """
    container_name = config["container_name"][container_type]
    Log.debug(f"Inspecting the current {container_name} container on: {get_name_and_ip(host)}")
    container_properties = host["container_properties"]
    current_version = host["current_version"]

    # Make the command to create new docker container before actually touching the containers
    command, image_name, image_version = build_create_command(host, config)

    current_container_name = retrieve_container_name(container_properties)
    if current_container_name == container_name:
        renamed = f"{container_name}_{current_version}"
        Log.debug(
            f"Renaming {container_name} docker container {container_name} to {renamed} on: {get_name_and_ip(host)}"
        )
        run_remote(host, f"docker rename {container_name} {renamed}")
        current_container_name = renamed
    else:
        Log.debug(
            f"Skipping to rename container {current_container_name} on: {get_name_and_ip(host)}"
        )
        renamed = None

    Log.debug(
        f"Creating {container_name} docker container for the next version on: {get_name_and_ip(host)}"
    )
    try:
        run_remote(host, command)
    except RuntimeError as error:
        if renamed:
            Log.error(
                f"Failed to create new {container_name} container from image {image_name}:{image_version}"
                f" on host {get_name_and_ip(host)}."
                f"\nEncountered exception: {str(error)}"
                f"\nRolling back to version: {current_version}"
            )
            run_remote(host, f"docker start {renamed}")
            run_remote(host, f"docker rename {renamed} {container_name}")
            # rethrow
            raise error

    if container_properties.get("State", {}).get("Running", False):
        Log.debug(
            f"Stopping current {container_name} docker container on: {get_name_and_ip(host)}"
        )
        run_remote(host, f"docker stop {current_container_name}")
    else:
        Log.debug(
            f"Current {container_name} docker container {current_container_name}"
            f" is stopped already on: {get_name_and_ip(host)}"
        )

    try:
        if run_post_create:
            run_post_create(host, config)
        Log.info(f"Starting the new {container_name} docker container on: {get_name_and_ip(host)}")
        run_remote(host, f"docker start {container_name}")
        wait_for_container_ready(host, config)
        # wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")
    except RuntimeError as error:
        if renamed:
            Log.error(
                f"Failed to upgrade {container_name} to version {image_version}"
                f" on host {get_name_and_ip(host)}."
                f"\nEncountered exception: {str(error)}"
                f"\nRolling back to version: {current_version}"
            )

            stop_broken_bios(host, "upgrade", config)
            run_remote(host, f"docker start {container_name}_{current_version}")
            run_remote(host, f"docker rename {container_name}_{current_version} {container_name}")

        # Clean-up old failures.
        result = run_remote(
            host,
            f'docker ps --all --filter "name={container_name}_failed_upgrade"'
            ' --format "table {{.Names}}"',
        )
        failed_containers = parse_string_table(result.stdout)
        max_container_count = config["upgrade_fail_history"]
        containers_to_clean = []
        # The results of `docker ps` are sorted in reverse chronological order of creation time.
        for index, name in enumerate(failed_containers["NAMES"]):
            if index >= max_container_count:
                containers_to_clean.append(name)

        for outdated_container in containers_to_clean:
            try:
                run_remote(host, f"docker rm {outdated_container}")
            except Exception as secondary_exception:
                # This is a non-fatal error, we merely log it and move on.
                Log.error(
                    f"Failed to remove old failed container {outdated_container} "
                    f"on host {get_name_and_ip(host)} because of error: {str(secondary_exception)}"
                )

        return False
    Log.info(
        f"Upgraded {container_name} from version {current_version} to version {image_version} on:"
        f" {get_name_and_ip(host)}"
    )
    return True


def pull_bios_image(index, host, config):
    """Pull the bios image for the version specified in the config.

    The method puts the retrieved image full name to config["image_full_name"] since
    the name may be something unexpected in case loading image file is specified.

    Args:
        index (int): Not used.
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
    """
    del index
    ver = config.get("target_version")
    container_info = get_docker_instance(config, host, CONTAINER_T_BIOS, ver=ver)
    config["image_full_name"] = container_info.image_url


def update_host_resources(host, resource_name, source, bios_version):
    """Update the downloadable docker image resources available from the UI.

    Args:
        host (LCM host object): The host on which to operate on.
        resource_name (string): Name of the resource to be updated.
        source (string): Path from where to pick the updated resource
        bios_version (string): Version of the updated resource.
    """
    filename = f"{resource_name}-{bios_version}.tar.gz"
    downloads_folder = "/var/www/downloads"
    resource_link = f"{downloads_folder}/{resource_name}.tar.gz"

    put_file(host, f"{source}/{filename}", "/tmp")
    run_remote(host, f"docker cp /tmp/{filename} bioslb:{downloads_folder}")
    # Accept error here in case the resource does not already exist.
    result = run_remote(host, f"docker exec bioslb readlink {resource_link} -s", [1])
    # This can be empty, but it is acceptable.
    old_resource = result.stdout.strip()
    run_remote(host, f"docker exec bioslb ln -sfT {downloads_folder}/{filename} {resource_link}")
    run_remote(host, f"docker exec bioslb rm -rf {old_resource}")


def update_lb_resources(index, host, config):
    """Update all resources available on load balancer node, as specified in the config.

    Args:
        index (int): Not used.
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
    """
    del index

    upgraded_version = config["bios_version"]
    upgrade_folder = f"{UPGRADE_RESOURCES_BASE_PATH}_{upgraded_version}"
    Log.info(f"Updating download resources on host: {get_name_and_ip(host)}")
    for resource in config["docker_image_downloads"]:
        update_host_resources(host, resource, upgrade_folder, upgraded_version)
        Log.info(f"Updated download resource {resource} on host {get_name_and_ip(host)}")


def save_docker_image(config, image_name, destination, bios_version):
    """Save a docker image as a tarball after pulling it.

    Args:
        config (dict): The cluster configuration.
        image_name (string): Name of the image to pull and save.
        destination (string): The destination where to save the tarball.
        bios_version (string): The bios version this image is applicable for.
    """
    lcm_node = config["roles"]["lcm"][0]
    image = get_docker_instance(config, lcm_node, image_name)
    run_local(f"docker save -o {destination}/{image_name}-{bios_version}.tar.gz {image.image_url}")
    run_local(f"chmod 777 {destination}/{image_name}-{bios_version}.tar.gz")


def docker_image_downloads_updated(config, upgraded_version):
    """Check if the download resources on all load balancer nodes are for the latest bios version.

    Args:
        config (dict): The cluster configuration.
        upgraded_version (string): The latest bios version.

    Returns:
        bool: True if resources up-to-date. False otherwise.
    """
    lb_nodes = config["roles"]["lb"]
    resource_list = config["docker_image_downloads"]
    downloads_folder = "/var/www/downloads"

    for host in lb_nodes:
        for resource_name in resource_list:
            resource_link = f"{downloads_folder}/{resource_name}.tar.gz"
            result = run_remote(host, f"docker exec bioslb readlink {resource_link} -s", [1])
            try:
                filename = result.stdout.strip().split("/")[-1]
                filename = filename.strip(".tar.gz")
                current_version = filename.split("-")[-1]
            except Exception:
                return False
            if upgraded_version != current_version:
                return False

    return True


def update_docker_image_downloads(config, target_version):
    """Fetch the latest docker images to distribute to the load balancer nodes.

    Args:
        config (dict): The cluster configuration.
        target_version (string): The version for which the docker images need to be fetched.
    """
    upgrade_folder = f"{UPGRADE_RESOURCES_BASE_PATH}_{target_version}"
    run_local(f"mkdir -p {upgrade_folder}")
    for resource in config["docker_image_downloads"]:
        save_docker_image(config, resource, upgrade_folder, target_version)
    lb_nodes = config["roles"]["lb"]
    execute_on_hosts(update_lb_resources, "Update downloadable resources", lb_nodes, config)


def upgrade_host(config):
    setup_connect_aliases(config)
    install_dependencies(config)
    reopen_connections(config)


def upgrade_ui(config: Dict[str, Any], options: Dict[str, str] = None):
    """Upgrade the UI code on all load balancer nodes of the cluster.

    Args:
        config (dict): The cluster configuration.
    """
    del options

    ui_filename = config["ui_filename"]
    upgrade_component_on_lb_hosts(config, ui_filename, "dist", "UI")


def upgrade_docs(config: Dict[str, Any], options: Dict[str, str] = None):
    """Upgrade the UI code on all load balancer nodes of the cluster.

    Args:
        config (dict): The cluster configuration.
    """
    del options

    docs_filename = config["docs_filename"]
    upgrade_component_on_lb_hosts(config, docs_filename, "docs", "Docs")


def upgrade_component_on_lb_hosts(
    config: Dict[str, Any], component_file_name: str, component_name: str, display_name: str
):
    """Generic method to upgrade a component in LB nodes.

    Args:
        config (Dict[str, Any]): The cluster configuration.
        component_file_name (str): The name of tgz file that archives the component.
        component_name (str): Component name in the destination.
        display_name (str): Name of the component that appears in log messages.
    """

    # Dynamic function that is executed for an LB node
    def upgrade_component_on_lb_host(index: int, host: Dict[str, str], config: Dict[str, Any]):
        del index

        Log.info(f"Applying {display_name} build {component_file_name} on {host['name']}")

        remote_res_path = get_container_resources_directory(
            host, config["lb_resources_dir"], "/var/ext_resources"
        )
        static_contents_path = f"{remote_res_path}/static_contents"
        backups_path = f"{remote_res_path}/static_contents.backups"

        # Download the component archive
        download_file(config, component_file_name, host, "/tmp")

        # Take backup of current component
        src = f"{static_contents_path}/{component_name}"
        has_component = component_name in run_remote(
            host, f"ls -1 {static_contents_path}"
        ).stdout.split("\n")
        backup_files = run_remote(host, f"ls -1 {backups_path}").stdout.split("\n")
        backups = sorted([file for file in backup_files if file.startswith(f"{component_name}-")])
        # Remove stale backups
        num_backups_to_leave = 4
        to_remove = backups[:-num_backups_to_leave]
        if to_remove:
            Log.debug(f"Removing stale backups: {to_remove}")
            paths_to_remove = " ".join([f"{backups_path}/{file}" for file in to_remove])
            run_remote(host, f"rm -rf {paths_to_remove}")

        if has_component:
            Log.debug(f"Taking backup of current component '{component_name}'")
            run_remote(
                host, f"mv {src} {backups_path}/{component_name}-$(date -u +%Y-%m-%d--%H-%M-%S)"
            )

        # Expand the new component
        run_remote(
            host,
            f"tar -xzf /tmp/{component_file_name} --directory={static_contents_path}/",
        )

    Log.info(f"Upgrading {display_name}")
    bioslb_nodes = config["roles"]["lb"]
    execute_on_hosts(
        upgrade_component_on_lb_host,
        f"Upgrade {display_name}",
        bioslb_nodes,
        config,
        parallel=False,
    )
    Log.info(f"Completed upgrading {display_name}")


def upgrade_sdk(config: Dict[str, Any], options: Dict[str, str]):
    """Upgrades python sdk"""
    del options

    activate_gcp_service_account()
    project = config["bios_container_registry_project"]
    repository = config["python_sdk_repository"]
    location = config["python_sdk_location"]
    package = config["python_sdk_package"]
    result = run_local(
        f"gcloud artifacts files list --project={project}"
        f" --repository={repository} --location={location} --package={package}"
    )
    entries = result.stdout.strip().split("\n")
    pattern = re.compile(
        f".* projects/{project}/locations/{location}/repositories/{repository}"
        f"/packages/{package}/versions/(.+)"
    )
    versions = []
    for entry in entries:
        matched = pattern.match(entry)
        if matched:
            versions.append(matched.group(1))
    versions.sort(key=Version)
    if not versions:
        Log.error("No versions of Python SDK found")
        return
    latest = versions[-1]
    package_prefix = config["python_sdk_package_prefix"]
    package_suffix = config["python_sdk_package_suffix"]
    package_file = f"{package}%2F{package_prefix}-{latest}-{package_suffix}"
    run_local(f"rm -f /tmp/{package_file}")
    Log.info(f"Downloading {package_file}")
    run_local(
        f"gcloud artifacts files download --project={project} --repository={repository}"
        f" --location={location} --destination=/tmp {package_file}"
    )
    Log.info(f"Installing python SDK version {latest}")
    run_local(f"pip3 uninstall -y {package}")
    run_local(f"pip3 install /tmp/{package_file}")


def stop_dbdozer():
    Log.info("  Stopping dbdozer ...")
    run_local("docker stop dbdozer")
    time.sleep(10)


def restart_sql_containers(config: Dict[str, Any]):
    compute_hosts = config["roles"]["compute"]
    for host in compute_hosts:
        sql_containers = []
        result = run_remote(host, "docker ps -a | grep bios-sql | awk '{ print $10 }'")
        for line in result.stdout.split("\n"):
            sql_containers.append(line.strip())
        Log.info("")
        result = input(f"  Restarting sql containers on host: {host['name']} - (yes/no)? ")
        if result.lower() not in ["yes", "y"]:
            Log.info(f"  Skipping bios restart on host: {host['name']}")
        else:
            for container in sql_containers:
                if container:
                    Log.info(f"  Restarting container: {container} on host: {host['name']}")
                    result = run_remote(host, f"docker restart {container}")
                    Log.info("  Sleeping for 30 seconds... ")
                    time.sleep(30)
                    Log.info("  Done")


def restart_bios_containers(config: Dict[str, Any]):
    bios_hosts = config["roles"]["storage"]
    for host in bios_hosts:
        Log.info("")
        result = input(f"  Restart bios on host: {host['name']} - (yes/no) ? ")
        if result.lower() not in ["yes", "y"]:
            Log.info(f"  Skipping bios restart on host: {host['name']}")
        else:
            run_remote(host, "docker restart bios")
            Log.info("  Restarted bios. Sleeping for 30 seconds... ")
            time.sleep(30)
            Log.info("  Done")


def restart_bios_storage_containers(config: Dict[str, Any]):
    bios_storage_hosts = config["roles"]["storage"]
    for host in bios_storage_hosts:
        Log.info("")
        result = input(f"  Restart bios-storage on host {host['name']} - (yes/no) ? ")
        if result.lower() not in ["yes", "y"]:
            Log.info(f"  Skipping bios-storage restart on host: {host['name']}")
        else:
            run_remote(host, "docker restart bios-storage")
            Log.info("  Restarted bios-storage. Sleeping for 90 seconds... ")
            time.sleep(90)
            Log.info("  Done")


def start_dbdozer():
    Log.info("  Starting dbdozer ...")
    run_local("docker start dbdozer")
    time.sleep(10)


def bios_certs(config: Dict[str, Any], options: Dict[str, str]):
    """Renew bios server certificates"""
    del options

    Log.info("Renew bios server certificates")

    # create a local directory for holding renewed certs and trust stores
    today = datetime.datetime.today()
    today_str = f"{today.month:02d}{today.day:02d}{today.year}"
    renewal_dir = f"/home/ubuntu/cert_renewals/certs_{today_str}"
    run_local(f"mkdir -p {renewal_dir}")
    cluster_dns_name = config["cluster_dns_name"]
    Log.info(f"  cluster_dns_name: {cluster_dns_name}")
    legacy_store = False
    if cluster_dns_name == "bios.isima.io":
        legacy_store = True

    # copy existing certs, create new stores and backup files
    fetch_certs_and_stores(config, cluster_dns_name, renewal_dir, legacy_store)
    update_trust_stores(renewal_dir, today_str, legacy_store)
    backup_certs_and_stores(config, today_str, legacy_store)

    # copy stores and restart containers
    stop_dbdozer()
    copy_new_certs_and_stores_to_targets(config, renewal_dir, legacy_store)
    restart_sql_containers(config)
    restart_bios_containers(config)
    restart_bios_storage_containers(config)
    replace_certs_and_restart_lb_nodes(config)
    start_dbdozer()

    Log.info("All Done.")
    Log.info("Completed renewing bios server certificates.")


def activate_gcp_service_account():
    """Activate service account in GCP"""
    Log.debug("Activating Google service account credentials")
    run_local(f"gcloud auth activate-service-account --key-file={CREDS_FILE}")


UPGRADING_METHODS = {
    "ui": upgrade_ui,
    "docs": upgrade_docs,
    "python-sdk": upgrade_sdk,  # caution: untested
    "bios-certs": bios_certs,  # caution: untested
    "bios": upgrade_bios,
    "bios-integrations": upgrade_integrations,
    "bios-maintainer": upgrade_maintainer,
    "bios-sql": upgrade_sql,
    "bios-storage": upgrade_storage,
}


def upgrade_components(
    config: Dict[str, Any], components_to_upgrade: List[str], options: Dict[str, str]
):
    """Executes upgrading the specified components."""
    for component in components_to_upgrade:
        upgrading_method = UPGRADING_METHODS.get(component)
        if not upgrading_method:
            raise ValueError(f"Unsupported component: {component}")
        upgrading_method(config, options)


def _usage():
    components = "".join([f"\n        {component}" for component in UPGRADING_METHODS])
    print(
        f"""

Usage:
  {sys.argv[0]} [options] host [host_names...]
          : Upgrade the specified components of a bi(OS) cluster.
  {sys.argv[0]} [options] [components...]
          : Upgrade the specified components of a bi(OS) cluster.

  options:
    -v: Print verbose logs

  options for bios:
    --image-file <file>: biOS image file name to be used for upgrading.
                         The file must be placed at 'resource_bucket'
                         in /isima/lcm/env/cluster_config.yaml. Absolute path is not allowed.
    --image-name: <name>: Specifies image name of biOS. Ignored if --image-file is set
    --version <ver>: Specifies version of upgrading biOS. Omitted if --image-file is set

  options for bios-integrations:
    --image-file <file>: Integrations image file to be used for upgrading.
                         The file must be placed at 'resource_bucket'
                         in /isima/lcm/env/cluster_config.yaml. Absolute path is not allowed.
    --list: Only lists installed tenants. Upgrading is not executed
    --tenants: Comma separated tenants to upgrade. Upgrades all installed tenants when omitted

  params:
    host: Only updates the host e.g. dependencies, aliases etc.
    host_names: The names of the hosts to upgrade, e.g. signal-2
    components: Component names. Currently supported components are:{components}

For detailed instructions, see /isima/lcm/lcm/README.md
    """
    )
    sys.exit(1)


def get_options(current_arg: int) -> Tuple[Dict[str, Union[str, bool]], int]:
    """Parses command line options"""
    options = {}
    # name: (name, take_argument)
    option_definitions = {
        "-v": ("verbose", False),
        "--version": ("version", True),
        "--image-name": ("image_name", True),
        "--image-file": ("image_file", True),
        "--rollback": ("rollback", False),
        "--keep": ("keep", False),
        "--list": ("list_only", False),
        "--tenants": ("tenants", True),
    }
    while current_arg < len(sys.argv):
        arg = sys.argv[current_arg]
        if not arg.startswith("-"):
            break
        definition = option_definitions.get(arg)
        if definition:
            if definition[1]:
                current_arg += 1
                if current_arg >= len(sys.argv):
                    _usage()
                options[definition[0]] = sys.argv[current_arg]
            else:
                options[definition[0]] = True
        else:
            print(f"Unknown option: {arg}")
            _usage()
        current_arg += 1
    return options, current_arg


def main():
    """The main program"""
    current_arg = 1
    if len(sys.argv) < 2:
        _usage()

    options, current_arg = get_options(current_arg)
    if options.get("verbose"):
        Log.set_verbose_output(True)

    config = initialize_lcm()

    if sys.argv[current_arg] == "host":
        hosts_to_upgrade = sys.argv[current_arg + 1 :]
        for host in hosts_to_upgrade:
            if host not in config["hosts"]:
                print(f"Host {host} is not defined in the cluster configuration.")
                _usage()
        # Edit config to remove all hosts that do not need to be upgraded.
        config["hosts"] = {host: config["hosts"][host] for host in hosts_to_upgrade}
        print(f"Upgrading the following hosts: {hosts_to_upgrade}")
        print(f"Config: {config}")
        upgrade_host(config)
    else:
        components_to_upgrade = sys.argv[current_arg:]
        for component in components_to_upgrade:
            if component not in UPGRADING_METHODS:
                _usage()
        upgrade_components(config, components_to_upgrade, options)

    Log.marker("Completed upgrading the bi(OS) cluster!")


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
