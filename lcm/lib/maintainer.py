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
"""Module that manages biOS maintenance"""

import json
import time

from lib.bios_container_common import retrieve_current_version
from lib.common import get_name_and_ip, parse_string_table, run_local
from lib.install_upgrade_common import build_docker_create_command, obtain_docker_image
from lib.log import Log


def upgrade_maintainer(config: dict, options: dict):
    """Upgrades bios maintenance container"""
    image_file = options.get("image_file")
    if image_file:
        config["image_file"] = image_file
    else:
        image_name = options.get("image_name", "bios-maintainer")
        target_version = options.get("version")
        if not image_name or not target_version:
            raise RuntimeError("Specify --image-file or --version option to upgrade")
        config["image_name"] = image_name
        config["target_version"] = target_version

    Log.info("Checking the running bios-maintainer container")
    host = config["roles"]["lcm"][0]
    node_string = get_name_and_ip(host)
    container_name = "bios-maintainer"
    result = run_local("docker ps -a")
    parsed = parse_string_table(result.stdout)
    if container_name not in parsed.get("NAMES", []):
        Log.error(f"biOS maintainer container '{container_name}' is not running on {node_string}")
        return
    result = run_local(f"docker inspect {container_name}")
    container_properties = json.loads(result.stdout)[0]

    Log.info("Obtaining the docker image")
    obtain_docker_image(0, None, config)
    if image_file:
        # determine the version number by the image tag
        image_full_name = config.get("image_full_name")
        target_version = image_full_name.split(":")[1]

    command, image_name, image_version = build_docker_create_command(
        config, container_name, container_properties
    )

    if image_file:
        target_version = image_version

    current_version = retrieve_current_version(container_properties)
    if current_version == target_version:
        Log.info(f"{container_name} container is version {target_version} already")
        return

    Log.info(f"Upgrading {container_name} on {node_string}")
    # remember number of log lines
    result = run_local("wc -l /var/log/bios-maintainer/*maintainer.log | awk '{{print $1}}'")
    initial_log_lines = int(result.stdout)
    renamed = f"{container_name}_{current_version}"
    run_local(f"docker rename {container_name} {renamed}")
    try:
        run_local(command)
        run_local(f"docker cp {renamed}:/root/.cassandra/nodetool-ssl.properties /tmp/")
        run_local(f"docker cp /tmp/nodetool-ssl.properties {container_name}:/root/.cassandra/")
        run_local(f"docker stop {renamed}")
        run_local(f"docker start {container_name}")
        Log.info(
            f"New {container_name} version {target_version} has started."
            " Sleeping for 20 seconds to wait for things settled"
        )
        time.sleep(20)
        result = run_local(
            "docker exec bios-maintainer supervisorctl status dbdozer", accepted_exit_codes=[3]
        )
        if result.return_code != 0:
            raise RuntimeError("Maintainer did not start after the upgrade")
        result = run_local("wc -l /var/log/bios-maintainer/*maintainer.log | awk '{{print $1}}'")
        current_log_lines = int(result.stdout)
        num_lines = current_log_lines - initial_log_lines
        result = run_local(
            f"tail -n {num_lines} /var/log/bios-maintainer/*maintainer.log | grep ERROR | wc -l"
        )
        if int(result.stdout) > 0:
            raise RuntimeError(f"{int(result.stdout)} errors are found after upgrading")
    except RuntimeError as err:
        Log.error("An error encountered while upgrading, rolling back")
        run_local(f"docker stop {container_name}", ignore_error=True)
        run_local(f"docker start {renamed}", ignore_error=True)
        run_local(
            f"docker rename {container_name} {container_name}_fail_{target_version}",
            ignore_error=True,
        )
        run_local(f"docker rename {renamed} {container_name}")
        # rethrow
        raise err
    Log.info(
        f"{container_name} was upgraded successfully to version {target_version} on {node_string}"
    )
