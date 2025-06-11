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
import re
import time
from typing import Any, Dict, List, Tuple

from lib.bios_container_common import (
    retrieve_binds,
    retrieve_container_name,
    retrieve_cpuset_cpus,
    retrieve_env,
    retrieve_extra_hosts,
    retrieve_memory,
    retrieve_port_bindings,
)
from lib.common import (
    add_logs_alias,
    append_line_if_absent,
    append_line_if_absent_local,
    execute_on_hosts,
    get_name_and_ip,
    open_new_connection,
    parse_string_table,
    run_local,
    run_remote,
    run_sudo_remote,
    to_bash_profile,
)
from lib.constants import CONTAINER_T_STORAGE, ISIMA_BASE_PATH, REMOTE_JOURNAL_PATH
from lib.docker_instance import load_docker_image
from lib.log import Log


def setup_connect_aliases(config):
    # Set up convenience aliases to login to each of the cluster VMs.
    for name, host in config["hosts"].items():
        if name == config["roles"]["lcm"][0]["name"]:
            continue
        optional_username = ""
        if "user" in host:
            optional_username = host["user"] + "@"
        to_bash_profile(
            config["roles"]["lcm"][0],
            f'alias connect-{name}="ssh -o StrictHostKeyChecking=no '
            f'{optional_username}{host["ip"]}"',
        )


def install_dependencies(config):
    """If a key pair for ssh does not exist on the LCM machine yet, generate it."""
    Log.info("Generating ssh key pair if needed.")
    run_local("test -f ~/.ssh/id_rsa.pub || ssh-keygen -f ~/.ssh/id_rsa -N ''")
    config["lcm_public_key"] = run_local("cat ~/.ssh/id_rsa.pub").stdout.strip()

    execute_on_hosts(
        install_dependencies_on_host,
        "Install dependencies",
        config["hosts"].values(),
        config,
    )
    if "lcm" in config["hosts"]:
        log_full_path = "/isima/lcm/log/trace_compact__all_hosts.log"
        add_logs_alias(config["hosts"]["lcm"], "logs-lcm-trace-compact", log_full_path)
        log_full_path = "/isima/lcm/log/trace_full__localhost.log"
        add_logs_alias(config["hosts"]["lcm"], "logs-lcm-full-localhost", log_full_path)
        to_bash_profile(config["hosts"]["lcm"], "source /isima/lcm/lcm_venv/bin/activate")
    for host in config["hosts"].values():
        append_line_if_absent_local("/etc/hosts", f"{host['ip']}    {host['name']}")


def install_dependencies_on_host(index, host, config):
    del index
    Log.debug(f"Installing dependencies on host: {get_name_and_ip(host)}")
    if config["lcm_names_are_same_as_kernel_hostname"]:
        run_sudo_remote(host, f"hostnamectl set-hostname {host['name']}")
    run_remote(host, "umask 0077 ; mkdir -p ~/.ssh")
    run_sudo_remote(host, f"mkdir -p {ISIMA_BASE_PATH}")
    run_sudo_remote(host, f"chown $USER:$USER {ISIMA_BASE_PATH}")
    run_remote(host, f"mkdir -p {REMOTE_JOURNAL_PATH}")
    append_line_if_absent(host, "~/.ssh/authorized_keys", config["lcm_public_key"])

    # Add convenience aliases and prompt.
    to_bash_profile(
        host,
        f'export PS1="\\D{{%H:%M:%S}} \\[\\033[34m\\]<{config["cluster_name"]}>'
        f' \\[\\033[32m\\]{host["name"]}:\\[\\033[33m\\]\\w\\[\\033[m\\]\\$ "',
    )
    to_bash_profile(host, 'export PROMPT_COMMAND="history -a"')
    to_bash_profile(host, 'alias ls="ls --color"')
    to_bash_profile(host, 'alias lst="ls --color -larth"')
    to_bash_profile(host, 'alias f="grep --color -r -i"')
    to_bash_profile(host, 'alias fl="grep --color -r -i -l"')
    to_bash_profile(host, 'alias ff="find . -type f -name"')
    to_bash_profile(host, 'alias vbp="vi ~/.bash_profile"')
    to_bash_profile(
        host,
        'docker_list_volume_mappings() { docker container inspect  -f "{{ range '
        '.Mounts }}{{ .Destination }} : {{ .Source }}           {{ end }}" $*; }',
    )
    append_line_if_absent(host, "$HOME/.bashrc", "source $HOME/.bash_profile")

    run_sudo_remote(host, "apt-get update")
    run_sudo_remote(
        host,
        "apt-get install -y --no-upgrade apt-transport-https ca-certificates gnupg netcat curl",
    )

    run_remote(
        host,
        "echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections",
    )
    Log.debug(f"Installing docker on: {get_name_and_ip(host)}")
    run_remote(
        host,
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg |"
        " sudo gpg --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
    )
    run_remote(
        host,
        'echo "deb [arch=$(dpkg --print-architecture)'
        " signed-by=/usr/share/keyrings/docker-archive-keyring.gpg]"
        ' https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" |'
        " sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
    )
    run_sudo_remote(host, "apt-get update")
    run_sudo_remote(
        host,
        "apt-get install -y --no-upgrade vim lsb-release docker-ce docker-ce-cli"
        " containerd.io docker-compose-plugin openjdk-11-jre-headless jq logrotate ncdu net-tools",
    )
    run_sudo_remote(host, "usermod -aG docker $USER")
    run_remote(host, 'echo "$USER   ALL=(ALL:ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers')

    Log.debug(f"Completed installing dependencies on host: {get_name_and_ip(host)}")


def reopen_connections(config):
    """Opens conections to all nodes in the cluster.

    Args:
        config (dict): The cluster configuration.
    """
    Log.info("Reopening connections to all hosts.")
    for name, host in config["hosts"].items():
        if host["connection"] is not None:
            Log.debug(f"Re-opening connection to host {name} ({host['ip']})")
            host["connection"].close()
            open_new_connection(host)
        else:
            Log.debug(f"Staring an ssh connection to localhost: {get_name_and_ip(host)}")
            open_new_connection(host)


def check_installed_containers(
    hosts: List[dict], container_name: str
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Get list of tenants where specified containers are installed.

    Returns: Dict[str, List[Tuple[str, Dict[str, Any]]]:
        {tenant_name: {host_name: container_properties}}
    """
    installed_tenants = {}
    pattern = re.compile(r"^.+[_-][0-9]+\..*")  # matches a backup of an old version
    for host in hosts:
        result = run_remote(host, f"docker ps -af 'name={container_name}-*'")
        parsed = parse_string_table(result.stdout)
        containers = parsed.get("NAMES", [])
        for container in containers:
            tenant = container[len(container_name) + 1 :]
            if tenant and not pattern.match(tenant):
                result = run_remote(host, f"docker inspect {container}")
                container_properties = json.loads(result.stdout)[0]
                installed_tenant = installed_tenants.setdefault(tenant, {})
                installed_tenant[host["name"]] = container_properties
    return installed_tenants


def determine_target_tenants(options: dict, installed_tenants: Dict[str, Dict[str, dict]]):
    """Determines target tenants"""
    specified_tenants = options.get("tenants").split(",") if "tenants" in options else []
    if specified_tenants:
        not_found_tenants = []
        for tenant in specified_tenants:
            if tenant not in installed_tenants:
                not_found_tenants.append(tenant)
        if not_found_tenants:
            raise RuntimeError(f"No such tenant(s): {not_found_tenants}")
        return specified_tenants

    # Tenant not specified explicitly. Select all available tenants
    return list(installed_tenants.keys())


def check_image_spec(options: dict, default_image_name: str) -> Tuple[str, str, str]:
    """Checks upgrade options for the specification for the Docker image used for upgrading.

    The method returns Docker image file name if specified by --image-file option.
    Else, the method returns image name and version by optional --image-name and required
    --version options. A RuntimeError is thrown if neither is specified.

    Args:
        options (dict): Upgrade options
        default_image_name (str): Default image name if --image-name option is not specified

    Returns: Tuple[str, str, str]:
      Tuple of image file name, image name, and version.

    Throws: RuntimeError to indicate that image specification is incomplete.
    """
    image_file = options.get("image_file")
    if image_file:
        return image_file, None, None

    image_name = options.get("image_name", default_image_name)
    target_version = options.get("version")
    if not image_name or not target_version:
        raise RuntimeError("Specify --image-file or --version option to upgrade")

    return None, image_name, target_version


def obtain_docker_image(index: int, host: dict, config: dict):
    """Download or upload docker images to be used for upgrading a bios component.

    This method is meant be used for a execute_on_hosts() callback, so has arguments
    index and host. But you can also call this method locally. In such a case,
    set None to host. The index is ignored.

    Args:
        index (int): Host index number
        host (dict): Host configuration
        config (dict): The cluster configuration
    """
    del index
    image_name = config.get("image_name")
    version = config.get("target_version")
    image_file = config.get("image_file")
    if image_file:
        image_full_name = load_docker_image(config, host, image_file)
        config["image_full_name"] = image_full_name
    else:
        run_remote(host, f"docker pull {image_name}:{version}")


def build_docker_create_command(
    config: dict,
    container_name: str,
    container_properties: Dict[str, Any],
    env_vars: List[str] = None,
    extra_params: List[str] = None,
) -> Tuple[str, str, str]:
    """Builds a command string to create the next version of bios component container.

    Args:
        config (dict): The cluster configuration
        container_name (str): Name of the container to be created
        container_properties (dict): Docker inspect content of the previous version
        env_vars (list): Names of environment variable names to be inherit from the previous version
        extra_params (list): Extra parameters to add explicitly

    Returns: str: Built docker create command string
    """
    components = [
        "docker create",
        f"--name {container_name}",
        "--restart unless-stopped",
    ]
    components.extend(extra_params or [])

    for extra_host in retrieve_extra_hosts(container_properties) or []:
        components.append(f"--add-host {extra_host}")

    if container_properties.get("HostConfig", {}).get("NetworkMode", "") == "host":
        components.append("--network host")

    for bind in retrieve_binds(container_properties) or []:
        components.append(f"-v {bind}")

    for port_binding in retrieve_port_bindings(container_properties):
        if port_binding:
            components.append(f"-p {port_binding}")

    env = retrieve_env(container_properties)
    if env_vars:
        env_names_to_retrieve = set(env_vars)
        for env_entry in env:
            elements = env_entry.split("=", maxsplit=2)
            if elements[0] in env_names_to_retrieve:
                components.append(f"-e {elements[0]}='{elements[1]}'")

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
        image_name = config.get("image_name", retrieve_container_name(container_properties))
        image_version = config["target_version"]
    components.append(f"{image_name}:{image_version}")

    command = " ".join(components)
    return command, image_name, image_version


def wait_for_db_cluster_formation(host, node_count, config, timeout=None):
    interval = 5
    if timeout is None:
        max_trials = node_count * 12
    else:
        max_trials = int(timeout / interval)
    bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    done = False
    tries = 0
    current_count = -99
    saved_err = ""
    while not done:
        try:
            result = run_remote(
                host,
                f"docker exec {bios_storage} /opt/db/bin/nodetool --ssl -u {config['db_jmx_user']}"
                f" -pw {config['db_jmx_password']} status 2>&1 | grep '^UN' | wc -l",
            )
            current_count = result.stdout.strip()
            if current_count == str(node_count):
                done = True
        except Exception as err:
            saved_err = str(err)
        if tries >= max_trials:
            raise RuntimeError(
                f"{bios_storage}: cluster did not form after waiting for {5 * tries} seconds;"
                f" got ({current_count}) nodes out of ({node_count}).\n{saved_err}"
            )
        time.sleep(5)
        tries += 1
