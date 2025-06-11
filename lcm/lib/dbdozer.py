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

from lib.common import (
    add_logs_alias,
    get_cluster_dns_name_port,
    get_log_path,
    get_name_and_ip,
    get_resources_path,
    put_file,
    replace_line_re,
    run_local,
    run_remote,
    run_remote_journal,
    run_sudo_remote,
)
from lib.constants import BIOS_CONFIGS_PATH, LOCAL_RES_PATH_BASE

from .docker_instance import get_docker_instance
from .log import Log


def configure_dbdozer(config):
    """Configure and install dbdozer"""
    dbdozer_host = config["roles"]["lcm"][0]
    Log.info(f"Configuring bios-maintainer on host: {get_name_and_ip(dbdozer_host)}")

    dbdozer_container = get_docker_instance(
        config, dbdozer_host, "bios-maintainer", image_available=True
    )
    dbdozer_resources_dir = get_resources_path(config, "dbdozer_resources_dir")
    dbdozer_log_dir = get_log_path(config, "dbdozer_log_dir")

    _cleanup_container(dbdozer_host, dbdozer_container)
    _prepare_dbdozer_yaml(config)
    _prepare_db_credentials_yaml(config)
    _send_resources(config, dbdozer_host, dbdozer_resources_dir, dbdozer_log_dir)
    _start_dbdozer(dbdozer_host, dbdozer_container, dbdozer_resources_dir, dbdozer_log_dir)


def _cleanup_container(host, dbdozer_container):
    Log.debug(f"Removing any old instance of the container if present -- {dbdozer_container.name}")
    run_remote(host, f"docker stop {dbdozer_container.name} || true")
    run_remote(host, f"docker rm {dbdozer_container.name} || true")


def _prepare_dbdozer_yaml(config):
    Log.debug(f"Copying and updating resource files into local directory: {LOCAL_RES_PATH_BASE}")
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/dbdozer.yaml {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/dbdozer.yaml"
    replace_line_re("DB_JMX_PORT", config["db_jmx_port"], file)
    nodetool_hosts = ""
    for storage_host in config["roles"]["storage"]:
        nodetool_hosts += f"\n      - {storage_host['ip']}"
    replace_line_re("NODETOOL_HOSTS", nodetool_hosts, file)
    storage_host = config["roles"]["storage"][0]
    if "user" in storage_host:
        vm_user = storage_host["user"]
    else:
        vm_user = os.environ["USER"]
    replace_line_re("VM_USER", vm_user, file)
    replace_line_re("CLUSTER_DNS_NAME", get_cluster_dns_name_port(config), file)
    server_hosts = ",".join(server_host["ip"] for server_host in config["roles"]["storage"])
    replace_line_re("SERVER_HOSTS", server_hosts, file)
    server_resources_dir = get_resources_path(config, "server_resources_dir")
    replace_line_re("SERVER_CONFIG_DIR", server_resources_dir, file)
    replace_line_re("DB_CLUSTER_NAME", config["cluster_name"], file)

    out_string = ""
    for host_ip, directories in config["host_data_file_directories"].items():
        out_string += f"\n      {host_ip}:"
        for directory in directories:
            out_string += f"\n        - {directory}"
    replace_line_re("HOST_DATA_FILE_DIRECTORIES", out_string, file)
    replace_line_re("SYSTEMADMIN_PASSWORD", config["systemadmin_password"], file)


def _prepare_db_credentials_yaml(config):
    Log.debug(
        f"Copying and updating DB credentials files into local directory: {LOCAL_RES_PATH_BASE}"
    )
    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db_credentials.yaml {LOCAL_RES_PATH_BASE}/"
    )
    file = f"{LOCAL_RES_PATH_BASE}/db_credentials.yaml"
    replace_line_re("DB_USER", config["db_user"], file)
    replace_line_re("DB_PASSWORD", config["db_password"], file)

    Log.debug(
        f"Copying and updating JMX credentials files into local directory: {LOCAL_RES_PATH_BASE}"
    )
    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/jmxremote.password {LOCAL_RES_PATH_BASE}/"
    )
    file = f"{LOCAL_RES_PATH_BASE}/db_credentials.yaml"
    file = f"{LOCAL_RES_PATH_BASE}/jmxremote.password"
    replace_line_re("DB_JMX_USER", config["db_jmx_user"], file)
    replace_line_re("DB_JMX_PASSWORD", config["db_jmx_password"], file)


def _send_resources(config, host, dbdozer_resources_dir, dbdozer_log_dir):
    run_sudo_remote(host, f"rm -rf {dbdozer_resources_dir}")
    run_sudo_remote(host, f"rm -rf {dbdozer_log_dir}")
    run_sudo_remote(host, f"mkdir -p {dbdozer_resources_dir}")
    run_sudo_remote(host, f"mkdir -p {dbdozer_log_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {dbdozer_resources_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {dbdozer_log_dir}")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/dbdozer.yaml", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db_credentials.yaml", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/jmxremote.password", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/cacerts.pem", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.truststore", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.pks12.keystore", f"{dbdozer_resources_dir}/")
    put_file(
        host, f"{os.environ['HOME']}/.ssh/id_rsa", f"{dbdozer_resources_dir}/vm_user.id_rsa.pem"
    )
    db_cluster_name = config["cluster_name"]
    put_file(host, f"{LOCAL_RES_PATH_BASE}/{db_cluster_name}.cer.pem", f"{dbdozer_resources_dir}/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/{db_cluster_name}.key.pem", f"{dbdozer_resources_dir}/")


def _start_dbdozer(host, dbdozer_container, dbdozer_resources_dir, dbdozer_log_dir):
    add_logs_alias(host, "logs-dbdozer", "dbdozer/dbdozer.log")
    cmd = (
        f"docker run -d --name {dbdozer_container.name} "
        f" --restart unless-stopped "
        f" -v {dbdozer_resources_dir}:/var/lib/bios-maintainer "
        f" -v {dbdozer_log_dir}:/var/log/bios-maintainer "
        f" {dbdozer_container.image_url}"
    )
    run_remote_journal(host, cmd, dbdozer_container.name)
    Log.debug("Completed configuring dbdozer")
