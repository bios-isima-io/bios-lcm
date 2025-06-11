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
from dataclasses import dataclass

from lib.common import (
    download_file,
    execute_on_hosts,
    get_name_and_ip,
    run_local,
    run_remote,
)
from lib.constants import CONTAINER_T_INTEGRATIONS, CONTAINER_T_LOAD, CONTAINER_T_SQL
from lib.log import Log


@dataclass
class DockerInstance:
    name: str
    image_url: str = None


def get_docker_instance(
    config: dict,
    host: dict,
    container_type: str,
    tenant: str = None,
    ver: str = None,
    image_available=False,
) -> DockerInstance:
    """Obtain the target image and container name on the host"""
    image_name = container_type
    name = config["container_name"].get(container_type) or container_type
    if container_type == "bios-integrations":
        image_name = "bios-integrations"
        name = f"{name}-{tenant}"
    elif container_type == CONTAINER_T_INTEGRATIONS:
        image_name = "bios-integrations"
        name = f"{name}-{tenant}"
    elif container_type == CONTAINER_T_LOAD:
        image_name = "bios-dev"
        name = f"{name}-{tenant}"
    elif container_type == CONTAINER_T_SQL:
        image_name = "bios-sql"
        name = f"{name}-{tenant}"

    if image_available:
        image_tag = config["images"][container_type]["tag"]
    else:
        image_file = config.get("image_file")
        if image_file:
            image_tag = load_docker_image(config, host, image_file)
        else:
            image_tag = pull_docker_image(config, host, image_name, ver)
    docker_instance = DockerInstance(name, image_tag)
    return docker_instance


def retabulate_version_numbers(config):
    """Updates the config to replace the "latest" tag for version with the actual version number
        and sets resource paths based on finalized version numbers taking into account overrides.

    Args:
        config (dict): The provided cluster configuration.
    """
    # hosts = config["hosts"]

    roles_to_image_types = {
        "lcm": ["bios-maintainer"],
        "storage": ["bios", "bios-storage"],
        "compute": ["bios-integrations", "bios-sql"],
        "lb": ["bioslb"],
    }

    all_hosts = {}
    all_image_specs = {}
    for role, hosts in config["roles"].items():
        image_properties = config["images"]
        image_types = roles_to_image_types.get(role)
        if not image_types:
            continue
        for host in hosts:
            all_hosts[host["name"]] = host
            for image_type in image_types:
                all_image_specs.setdefault(host["name"], {})[image_type] = image_properties[
                    image_type
                ]

    execute_on_hosts(
        obtain_docker_images,
        "Obtain docker images",
        list(all_hosts.values()),
        (config, all_image_specs),
    )

    config["latest_bios_version"] = "NotCalculated"


def obtain_docker_images(index, host, params):
    del index
    config, all_image_specs = params
    image_specs = all_image_specs[host["name"]]
    for image_properties in image_specs.values():
        file_name = image_properties.get("file")
        if file_name:
            image_tag = load_docker_image(config, host, file_name)
        else:
            image_tag = image_properties["tag"]
            if ":" not in image_tag:
                imagee_tag += f":{config['bios_version']}"
            run_remote(host, f"docker pull {image_tag}")
        image_properties["tag"] = image_tag
        elements = image_tag.split(":")
        image_properties["image_name"] = elements[0]
        image_properties["image_version"] = elements[1]


def load_docker_image(config: dict, host: dict, image_file: str):
    """Load image from file onto the host. Set None to the host to load locally"""
    download_file(config, image_file, host, "/tmp")
    remote_image_file = f"/tmp/{os.path.basename(image_file)}"
    initial_command = "gunzip -c" if remote_image_file.endswith(".gz") else "cat"
    command = f"{initial_command} {remote_image_file} | docker load | awk '{{print $3}}'"
    try:
        result = run_remote(host, command) if host else run_local(command)
        image_tag = result.stdout.strip()
    finally:
        run_remote(host, f"rm -f {remote_image_file}")
    return image_tag


def pull_docker_image(config: dict, host: dict, image_name: str, ver: str = None) -> str:
    """Pull docker image from network onto the host"""
    registry_hostname = config["bios_container_registry"]
    project = config["bios_container_registry_project"]
    if ver:
        tag = ver
    elif image_name in config["image_version"]:
        tag = config["image_version"][image_name]
    else:
        tag = config["bios_version"]

    image_url = f"{registry_hostname}/{project}/{image_name}:{tag}"

    Log.debug(f"Pulling container image {image_url} on: {get_name_and_ip(host)}")
    run_remote(host, f"docker pull {image_url}")

    return image_url
