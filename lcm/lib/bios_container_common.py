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

import json
import time
from typing import Any, Dict, List

import bios
import yaml
from lib.common import (
    get_lcm_path,
    get_name_and_ip,
    get_resources_path,
    if_not_auto,
    parse_string_table,
    run_local,
    run_remote,
    run_remote_journal,
    wait_for_bios_up,
)
from lib.common_with_bios import create_bios_session_system
from lib.constants import (
    BIOS_CONFIGS_PATH,
    BIOS_CONTAINER_READY_MARKER_PREFIX,
    BIOS_RESOURCES_COMPLETION_MARKER,
    CONTAINER_T_BIOS,
    CONTAINER_T_STORAGE,
    LOCAL_RES_PATH_BASE,
)
from lib.log import Log
from packaging import version


def repair_bios_node(host, config, bios_version=None):
    """Repairs bios by creating a new container with the most recent version of bios usable, or
        the one requested.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): Version to fallback to. Defaults to None, which means
                most current available.

    Raises:
        Exception: In case of a failure in repair, due to no installations available, or otherwise.
    """
    if bios_version:
        try:
            run_bios_on_host(host, config)
        except Exception as exception:
            raise Exception(
                f"Failed to restore node {get_name_and_ip(host)} to version {bios_version}!!!"
            ) from exception
    else:
        candidate_versions = bios_candidates(host, config)
        if not candidate_versions:
            raise Exception(
                f"Repair: no complete installation from earlier"
                f" found on node {get_name_and_ip(host)}."
                f" Please restore or upgrade (or both) bios."
            )

        chosen_version = candidate_versions[0]
        Log.info(
            f"Repairing bios by installing version {chosen_version} "
            f"on host {get_name_and_ip(host)}"
        )
        try:
            run_bios_on_host(host, config)
        except Exception as exception:
            raise Exception(f"Failed to repair node {get_name_and_ip(host)}!!!") from exception


def current_bios_version(host, config):
    """Gets the current running version of bios on host.

    Args:
        host (LCM host object): The host on which to operate on.

    Raises:
        Exception: In case of not being able to connect to the node.

    Returns:
        bios_version (string): The current running version of bios on the host.
    """
    try:
        bios_container = config["container_name"][CONTAINER_T_BIOS]
        result = run_remote(host, "docker inspect --format='{{.Config.Image}}' " + bios_container)
    except Exception as exception:
        if "No such object" in str(exception):
            Log.error(f"bios container not running on host: {get_name_and_ip(host)}.")
            return "None"
        raise RuntimeError(f"Error on host {get_name_and_ip(host)}") from exception

    bios_version = result.stdout.strip().split(":")[-1]
    return bios_version


def check_container(host, config, container_type, version_string=None):
    """Retrieves a container info.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        container_type (string): Container type
        version_string (string, optional): Version to check. Defaults to None, which means current.

    Raises:
        Exception: In case of not being able to connect to the node.

    Returns: Tuple[string, Dict[string, Any]]
        container_status, all container properties
    """
    container_name = config["container_name"][container_type]
    if version_string:
        container_name += f"_{version_string}"
    result = run_remote(host, f"docker inspect {container_name}")
    properties_src = result.stdout
    properties = json.loads(properties_src)[0]
    return properties.get("State", {}).get("Status", ""), properties


def retrieve_container_name(container_properties: Dict[str, Any]) -> str:
    """Fetches docker container name from a container properties"""
    return container_properties.get("Name", "/")[1:]


def retrieve_current_version(container_properties: Dict[str, Any]) -> str:
    """Fetches docker image's version from a container properties"""
    return container_properties.get("Config", {}).get("Image", ":").split(":")[1]


def retrieve_binds(container_properties: Dict[str, Any]) -> List[str]:
    """Fetches docker container's binds from a container properties"""
    return container_properties.get("HostConfig", {}).get("Binds")


def retrieve_port_bindings(container_properties: Dict[str, Any]) -> List[str]:
    """Fetches docker container's binds from a container properties"""
    port_bindings = []
    conf = container_properties.get("HostConfig", {}).get("PortBindings", {})
    for entry_key, entry_value in conf.items():
        if entry_key.endswith("/tcp"):
            internal_port = entry_key[:-4]
            for external in entry_value:
                host_ip = external.get("HostIp")
                host_port = external.get("HostPort")
                port_bindings.append(
                    f"{host_ip}:{host_port}:{internal_port}"
                    if host_ip
                    else f"{host_port}:{internal_port}"
                )
    return port_bindings


def retrieve_env(container_properties: Dict[str, Any]) -> List[str]:
    """Fetches environment variables from a container properties"""
    return container_properties.get("Config", {}).get("Env", [])


def retrieve_extra_hosts(container_properties: Dict[str, Any]) -> List[str]:
    """Fetches docker container's extra hosts from a container properties"""
    return container_properties.get("HostConfig", {}).get("ExtraHosts")


def retrieve_memory(container_properties: Dict[str, Any]) -> str:
    """Fetches docker container's memory size from a container properties"""
    return container_properties.get("HostConfig", {}).get("Memory")


def retrieve_cpuset_cpus(container_properties: Dict[str, Any]) -> str:
    """Fetches docker container's cpuset from a container properties"""
    return container_properties.get("HostConfig", {}).get("CpusetCpus")


def handle_failed_start(host, config, bios_version=None, repair=False):
    """Called when a bios container fails to start, either returns, or tries to reapir it based on
        the repair parameter value.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): Version to fallback to. Defaults to None, which means
                the current version.
        repair (bool, optional): Whether to repair in case a problem is found. Defaults to False.

    Raises:
        Exception: In case of a failure due to any reason.
    """
    container_name = config["container_name"][CONTAINER_T_BIOS]
    if bios_version:
        container_name = f"bios_{bios_version}"

    Log.error(f"Old bios container on node {get_name_and_ip(host)} is non-functional!")
    Log.info(f"\nRenaming unusable container to relfect it is broken")
    run_remote(
        host,
        f"docker rename {container_name} {container_name}_broken_{time.strftime('%Y%m%d_%H%M%S')}",
    )

    if repair:
        Log.info(
            f"Creating a new bios container on node {get_name_and_ip(host)} to repair system."
        )
        repair_bios_node(host, config, bios_version)
    else:
        raise Exception(f"Failed to start bios on node {get_name_and_ip(host)}")


def start_bios_container(host, config, bios_version=None, repair=False):
    """Tries to start an existing bios container. In case of a failure, calls handle_failed_start.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): Version of bios to start. Defaults to None, which means
                the current version.
        repair (bool, optional): Whether to repair in case a problem is found. Defaults to False.

    Raises:
        Exception: In case of a failure when the repair flag is not set.
    """
    max_attempts = 3
    attempt_count = 0
    wait_time = 60

    container_name = config["container_name"][CONTAINER_T_BIOS]
    if bios_version:
        run_remote(host, f"docker rename {container_name}_{bios_version} bios")

    try:
        while True:
            run_remote(host, f"docker start {container_name}")
            # Wait for container to come up.
            time.sleep(wait_time)
            # Query new status.
            result = run_remote(
                host, "docker inspect --format='{{.State.Status}}' " + container_name
            )
            new_status = result.stdout.strip()
            attempt_count += 1
            if new_status == "running":
                break
            if attempt_count > max_attempts:
                raise RuntimeError(f"Exceeded maximum container restart attempts.")
    except Exception as exception:
        Log.error(
            f"bios container on node {get_name_and_ip(host)} not functioning!"
            f"\nException: {str(exception)}"
        )
        handle_failed_start(host, config, repair=repair)


def diagnose_and_repair_bios_node(host, config, bios_version=None):
    """Checks bios health on the host and attempts to repair it in case something is wrong.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): Version of bios to diagnose. Defaults to None, which means
                the current version.
    """

    container_status, container_properties = check_container(
        host, config, CONTAINER_T_BIOS, version_string=bios_version
    )
    running_version = retrieve_current_version(container_properties)

    if container_status == "running":
        Log.info(
            f"Host {get_name_and_ip(host)} has bios container running properly."
            f"\nThe version is {running_version}"
        )
    # Try restarting the container to see if it works. If not, try to repair the installation
    elif container_status == "exited":
        start_bios_container(host, config, bios_version=bios_version, repair=True)


def bios_status(host, config):
    """Returns the current bios version and its health.

    Args:
       host (LCM host object): The host on which to operate on.

    Returns:
        current_version (string): The current version of bios running on the host
    """
    current_version = current_bios_version(host, config)
    if current_version == "None":
        return current_version, False
    return current_version


def report_bios_status(config):
    """Prints the status of all nodes in the cluster serially.

    Args:
        config (dict): The cluster configuration.
    """
    storage_nodes = config["roles"]["storage"]

    # For better readability and visual appeal
    Log.info("\n\nThe cluster status is:\n")

    for host in storage_nodes:
        Log.info(f"Status for node {get_name_and_ip(host)}:\n")

        current_version = bios_status(host, config)
        Log.info(f"The installed version of bios is: {current_version}")

        # TODO(pradeep) Get status into result.
        result = ""

        deployment_details = parse_string_table(result)
        deployed_version = deployment_details["NAME"][0].strip()
        deployed_status = deployment_details["STATUS"][0].strip()
        Log.info(f"The deployed version of bios is: {deployed_version}")
        Log.info(f"The deployment status is: {deployed_status}\n")

        candidate_versions = bios_candidates(host, config)
        if current_version in candidate_versions:
            candidate_versions.remove(current_version)
        Log.info(f"Available versions of bios are: ")
        for index, candidate in enumerate(candidate_versions):
            Log.info(f"[{index+1}] {candidate}")
        if not candidate_versions:
            Log.info(f"None")
        print(f"\n")


def bios_candidates(host, config):
    """Returns the available version of bios on the host.

    Args:
        host (LCM host object): The host on which to operate on.

    Raises:
        Exception: In case there is an error reaching the node.

    Returns:
        candidate_versions (list[string]): List of versions available on the node.
    """
    candidate_versions = []
    resource_list = run_remote(host, f"ls -d {config['isima_base_path']}/*/").stdout.split()
    Log.debug(f"Resource list found: {resource_list}")
    for resource_path in resource_list:
        # Get folder name from the path.
        resource_name = resource_path[:-1].split("/")[-1]
        components = resource_name.split("-")
        name = components[0]
        if name != "bios":
            Log.debug(f"Skipping resource {resource_path} as name: {resource_name}")
            continue
        bios_ver = components[1]

        try:
            Log.debug(f"Found version {bios_ver}, checking if usable.")
            run_remote(host, f"ls {resource_path}{BIOS_RESOURCES_COMPLETION_MARKER}")
        except Exception as exception:
            if "No such file or directory" in str(exception):
                Log.info(
                    f"Resources marker for bios version {bios_ver} not found on host:"
                    f" {get_name_and_ip(host)}, which may indicate incomplete resources."
                    f" Clean-up recommended."
                )
            else:
                raise exception
        else:
            candidate_versions.append(bios_ver)

    candidate_versions = sorted(candidate_versions, key=version.parse, reverse=True)
    return candidate_versions


def stop_broken_bios(host, procedure, config):
    """Stops and renames an unsuccessfully created bios container.

    Args:
        host (LCM host object): The host on which to operate on.
        procedure (string): The procedure which produced the broken container.

    Raises:
        Exception: In case of failure.
    """
    container_name = config["container_name"][CONTAINER_T_BIOS]
    try:
        run_remote(host, f"docker stop {container_name}")
    except Exception as exception:
        if "No such container" in str(exception):
            Log.info("A new bios container was not made.")
        else:
            raise RuntimeError(
                "Failed during rollback!! System in irrepairable state! Please reinstall bios."
            ) from exception
    run_remote(
        host,
        f"docker rename {container_name}"
        f" {container_name}_failed_{procedure}_{time.strftime('%Y%m%d_%H%M%S')}",
    )


def stop_bios_container(host, config, bios_version=None):
    """Stops the running bios version and suffixes it with its version number.
        Returns the name of the stopped container.


    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): Version of bios to stop. Defaults to None, which means
                the current version.

    Raises:
        Exception: In case of a failure.

    Returns:
        stopped_container (string): Name of the stopped container.
    """
    if not bios_version:
        bios_version = current_bios_version(host, config)

    container_name = config["container_name"][CONTAINER_T_BIOS]
    run_remote(host, f"docker stop {container_name}")
    stopped_container = f"{container_name}_{bios_version}"

    try:
        run_remote(host, f"docker rename {container_name} {stopped_container}")
    except Exception as exception:
        if "already in use" in str(exception):
            if config["retain_redundant_containers"]:
                run_remote(
                    host,
                    f"docker rename {stopped_container}"
                    f" {container_name}_{bios_version}_{time.strftime('%Y%m%d_%H%M%S')}",
                )
            else:
                run_remote(host, f"docker rm {stopped_container}")

            run_remote(host, f"docker rename {container_name} {stopped_container}")
        else:
            raise RuntimeError("Error renaming old bios container!") from exception

    return stopped_container


# TODO(pradeep) Used only by upgrade - move to upgrade_bios.py?
def login_to_bios_cluster(config):
    """Uses the python SDK to login into bi(OS).

    Args:
        config (dict): The cluster configuration.
    """
    Log.info(
        f"Using bi(OS) Python SDK to login to cluster using DNS name {config['cluster_dns_name']}"
    )
    try:
        create_bios_session_system(config)
    except Exception as err:
        Log.error(
            f"Could not login to cluster; verify that firewall allows access to TCP port 443"
            f" on machines pointed to by {config['cluster_dns_name']}"
        )
        Log.debug(str(err))


def create_starter_reports(config):
    """Reads the json file from the config path and creates user reports as described there.

    Args:
        config (dict): The cluster configuration.
    """
    Log.info("Creating observability reports in _system tenant")
    session = create_bios_session_system(config)
    reports = {}
    with open(f"{BIOS_CONFIGS_PATH}/reports.json", encoding="UTF-8") as reports_file:
        reports = json.load(reports_file)
    for report in reports["reportConfigs"]:
        session.put_report_config(report)


def save_host_details(config):
    """Saves the updated host details.

    Args:
        config (dict): The cluster configuration.
    """
    Log.info("Saving host details to file.")
    hosts_out = {}
    for name, host in config["hosts"].items():
        hosts_out[name] = {}
        hosts_out[name]["name"] = name
        hosts_out[name]["ip_address"] = host["ip"]
        hosts_out[name]["num_cpus"] = host["cpu_count"]
        hosts_out[name]["memory_gb"] = host["memory_gb"]
        if "cloud" in host:
            cloud = host["cloud"]
        elif "cloud" in config:
            cloud = config["cloud"]
        else:
            cloud = "None"
        hosts_out[name]["cloud"] = cloud

        if is_host_in_role(host, "storage", config):
            hosts_out[name]["role"] = "storage"
        elif is_host_in_role(host, "lb", config):
            hosts_out[name]["role"] = "lb"
        elif is_host_in_role(host, "compute", config):
            hosts_out[name]["role"] = "compute"
        elif is_host_in_role(host, "load", config):
            hosts_out[name]["role"] = "load"
        elif is_host_in_role(host, "lcm", config):
            hosts_out[name]["role"] = "lcm"
        else:
            hosts_out[name]["role"] = "None"

        if is_host_in_role(host, "storage", config):
            hosts_out[name]["sub_role"] = host["sub_role"]
        else:
            hosts_out[name]["sub_role"] = hosts_out[name]["role"]

        result = run_remote(host, "hostname")
        hostname = result.stdout.strip()
        hosts_out[name]["hostname"] = hostname

    with open(f"{get_lcm_path()}/../env/details_of_hosts.yaml", "w", encoding="UTF-8") as outfile:
        yaml.dump(hosts_out, outfile)

    Log.info("Saving host details to bi(OS) context.")
    session = create_bios_session_system(config)
    context_entries = []
    for host in hosts_out.values():
        attributes = [
            host["hostname"],
            host["name"],
            host["role"],
            host["sub_role"],
            host["cloud"],
            host["ip_address"],
            str(host["num_cpus"]),
            str(host["memory_gb"]),
        ]
        entry = ",".join(attributes)
        context_entries.append(entry)
    request = bios.isql().upsert().into("host").csv_bulk(context_entries).build()
    session.execute(request)

    Log.info("Saving mountpoint details to bi(OS) context.")
    context_entries = []
    context_entries.append(f"/,boot,{config['boot_disk_type']}")
    context_entries.append("/boot/efi,ignore,ignore")
    context_entries.append("/mnt,ignore,ignore")
    context_entries.append(f"{config['logs_dir']},commitLog,{config['logs_disk_type']}")
    for i in range(1, 65):
        context_entries.append(f"{config['data_dir_prefix']}{i},data,{config['data_disk_type']}")
    request = bios.isql().upsert().into("mountpoint").csv_bulk(context_entries).build()
    session.execute(request)


def populate_email_domains(config):
    """Populates prohibited email domains for signup.

    Args:
        config (dict): The cluster configuration.
    """
    Log.info("Populating prohibited email domains for signup.")
    session = create_bios_session_system(config)
    with open(f"{BIOS_CONFIGS_PATH}/domains.csv", "r", encoding="UTF-8") as file:
        context_entries = [entry.strip() for entry in file]
    request = bios.isql().upsert().into("_emailDomains").csv_bulk(context_entries).build()
    session.execute(request)


def is_host_in_role(host, role, config):
    """Checks if the node has the provided role or not.

    Args:
        host (LCM host object): The host on which to operate on.
        role (string): The role to check.
        config (dict): The cluster configuration.

    Returns:
        bool : Whether the role is applicable to the node.
    """
    if role in config["roles"]:
        for candidate_host in config["roles"][role]:
            if host["name"] == candidate_host["name"]:
                return True
    return False


def create_bios_start_cmd(host, config, bios_image):
    """Used to create the docker command to start a new bios container.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_image (string): The bios image tag.

    Returns:
        string: The command to run.
    """
    container_name = config["container_name"][CONTAINER_T_BIOS]
    cpuset = if_not_auto(
        config["server_cpuset"],
        f"{host['bios_storage_cpus']}-{host['bios_storage_cpus'] + host['bios_cpus'] - 1}",
    )
    memory = if_not_auto(config["server_memory"], f"{host['bios_memory']}g")
    server_resources_dir = get_resources_path(config, "server_resources_dir")
    cmd = (
        f"docker run --name {container_name} -d "
        f" --restart unless-stopped "
        f" --memory={memory} "
        f" --cpuset-cpus={cpuset} "
        f" --network host "
        f" -v {server_resources_dir}:/opt/bios/configuration "
        f" -v {config['logs_dir']}/log/server:/var/log/server "
        f" {bios_image}"
    )

    return cmd


def register_endpoint(host, config, sub_role):
    """Registers a node as a storage node of type sub_role by adding an entry in the cassandra
        database.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        sub_role (string):

    """
    url = f"https://{host['ip']}:{config['https_port']}/bios/v1/auth/login"
    # For first-install, use the default password.
    password = "systemadmin"
    # TODO(pradeep) For non-first-install, used the configured password.
    # password = config["systemadmin_password"]
    cmd = f"""curl -v --cacert {LOCAL_RES_PATH_BASE}/cacerts.pem -s \
        -d '{{"email":"systemadmin@isima.io","password":"{password}"}}' \
        -H "Content-Type: application/json" \
        -X POST "{url}" \
        | jq -r .token \
        """
    result = run_local(cmd)
    token = result.stdout.strip()

    endpoint = f"https://{host['ip']}:{config['https_port']}"
    cmd = f""" \
        curl -k -s -d '{{"operation":"add","endpoint":"{endpoint}","nodeType":"{sub_role}"}}' \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer {token}" \
        -X POST "{endpoint}/bios/v1/admin/endpoints" \
        """
    run_local(cmd)


def mark_bios_as_ready(host, config):
    """Put a marker for a running container to indicate it is ready for use.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
    """
    container_name = config["container_name"][CONTAINER_T_BIOS]
    container_id = run_remote(host, f"docker ps -aqf 'name=^{container_name}$'").stdout.strip()
    server_resources_dir = get_resources_path(config, "server_resources_dir")
    run_remote(
        host, f"touch {server_resources_dir}/{BIOS_CONTAINER_READY_MARKER_PREFIX}_{container_id}"
    )


def configure_bios_on_storage_node(index, host, config):
    """Initializes a node to be used as a bios storage node.

    Args:
        index (int): Index number of the node, used to decide the storage. sub-role.
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
    """
    Log.debug(f"Configuring bi(OS) on storage node {get_name_and_ip(host)}.")
    sub_role_index = index % len(config["sub_roles"])
    sub_role = config["sub_roles"][sub_role_index]
    wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")
    register_endpoint(host, config, sub_role)
    mark_bios_as_ready(host, config)
    Log.debug(f"Completed configuring bi(OS) on storage node {get_name_and_ip(host)}.")


def wait_for_db_up(index, host, config):
    """Wait for bios db to come up.

    Args:
        host (LCM host object): The host on which to operate on.

    Raises:
        Exception: In case bios-storage is unreachable even after multiple tries.
    """
    del index
    db_up = False
    tries = 0
    while not db_up:
        try:
            run_remote(host, f"nc -z localhost {config['db_port']}")
            db_up = True
        except Exception as exception:
            if tries >= 60:
                raise RuntimeError(
                    f"{config['container_name'][CONTAINER_T_STORAGE]} did not come up"
                    f" after waiting for 5 * {tries} seconds."
                ) from exception
            time.sleep(5)
            tries += 1


def run_bios_on_host(host, config, first_install=False):
    """Creates, deploys, and configures a new bios container.

    Args:
        host (LCM host object): The host on which to operate on.
        config (dict): The cluster configuration.
        bios_version (string, optional): The version of bios to run. Defaults to None, meaning the
                one mentioned in the config.
        first_install (bool, optional): Whether this is the first install, in which case the
                endpoints need to be registered. Defaults to False.
    """
    bios_image = config["images"]["bios"]["tag"]

    # Deploy the bios container.
    Log.debug("Starting a new container for bios")
    cmd = create_bios_start_cmd(host, config, bios_image)
    run_remote_journal(host, cmd, "bios")

    if first_install:
        return

    if config["rewrite_bios_addresses"]:
        configure_bios_on_storage_node(0, host, config)
    else:
        mark_bios_as_ready(host, config)
