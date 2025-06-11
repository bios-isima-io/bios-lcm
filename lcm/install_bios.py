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
import ssl
import sys
import time
from typing import Any, Dict

from lib.bios_apps import configure_apps, configure_sql
from lib.bios_container_common import (
    configure_bios_on_storage_node,
    create_starter_reports,
    populate_email_domains,
    report_bios_status,
    run_bios_on_host,
    save_host_details,
    wait_for_db_up,
)
from lib.common import (
    add_logs_alias,
    create_data_volume_init_command,
    create_logs_volume_init_command,
    download_file,
    execute_on_hosts,
    execute_wrapped,
    get_db_data_dir_numbers,
    get_log_path,
    get_name_and_ip,
    get_resources_path,
    if_not_auto,
    initialize_lcm,
    load_yaml_file,
    put_file,
    replace_line,
    replace_line_re,
    run_local,
    run_remote,
    run_remote_journal,
    run_sudo_remote,
    save_yaml_file,
    to_bash_profile,
    wait_for_bios_up,
)
from lib.common_with_bios import create_bios_session, create_bios_session_system
from lib.constants import (
    BIOS_CONFIGS_PATH,
    BIOS_RESOURCES_COMPLETION_MARKER,
    CACHE_DIR,
    CERT_FILE,
    CONTAINER_T_BIOS,
    CONTAINER_T_DEV,
    CONTAINER_T_LB,
    CONTAINER_T_LOAD,
    CONTAINER_T_MAINTAINER,
    CONTAINER_T_STORAGE,
    DATA_DIR,
    KEY_FILE,
    LCM_DIR,
    LOCAL_JOURNAL_PATH,
    LOCAL_RES_PATH_BASE,
    PORTS_FILE,
    REMOTE_JOURNAL_PATH,
)
from lib.dbdozer import configure_dbdozer
from lib.docker_instance import get_docker_instance, retabulate_version_numbers
from lib.fluentbit import configure_fluentbit
from lib.install_upgrade_common import (
    install_dependencies,
    reopen_connections,
    setup_connect_aliases,
    wait_for_db_cluster_formation,
)
from lib.log import Log
from lib.schema import initialize_system_schema


def _usage():
    command = os.path.basename(sys.argv[0])
    print(
        f"""

Usage:
    {command} install [verbose]
            : install a bi(OS) cluster.

    {command} clean [verbose]
            : cleanup a bi(OS) cluster.

    {command} status [verbose]
            : report the installation status of a bi(OS) cluster listing the current installation
              as well as the list of available bios versions on it.

    {command} validate [verbose]
            : do not install; only validate the inputs and hosts.

    verbose: optionally print verbose logs

Ensure the following files are updated in {DATA_DIR} directory:
    * hosts.yaml
    * cluster_config.yaml
    * web.cert.pem
    * web.key.pem
    * tenant.yaml

For detailed instructions, see {LCM_DIR}/README.md
    """
    )
    sys.exit(1)


def _set_common_name(common_name: str, common_names: Dict[str, Any]):
    src = f".{common_name}"
    components = src.split(".")
    current = common_names
    for component in reversed(components):
        current = current.setdefault(component, {})


def _verify_common_name(common_name: str, common_names: Dict[str, Any]) -> bool:
    components = common_name.split(".")
    current_node = common_names
    for component in reversed(components):
        next_node = current_node.get(component)
        if next_node is None:
            if "*" in current_node:
                return True
            return False
        current_node = next_node
    # The common name is valid if you find a leaf node
    return "" in current_node


def validate_cert_file(config, cert_file):
    Log.info(f"Checking whether {cert_file} contains domain name {config['cluster_dns_name']}")
    certificates = ssl._ssl._test_decode_cert(cert_file)
    common_names = {}
    names = set()
    if "subjectAltName" not in certificates:
        common_name = certificates["subject"][0][0][1]
        _set_common_name(common_name, common_names)
        names.add(certificates["subject"][0][0][1])
    else:
        for name_pair in certificates["subjectAltName"]:
            _set_common_name(name_pair[1], common_names)
            names.add(name_pair[1])

    # if config["cluster_dns_name"] not in names:
    if not _verify_common_name(config["cluster_dns_name"], common_names):
        message = (
            f"Certificate file {cert_file} does not contain"
            f" required DNS name {config['cluster_dns_name']}; it contains {names}"
        )
        if config["allow_invalid_cert_file"]:
            Log.error(message)
        else:
            raise Exception(message)
    wildcard_dns_name = f"*.{config['cluster_dns_name']}"
    if not _verify_common_name(wildcard_dns_name, common_names):
        Log.error(
            f"Certificate file {cert_file} does not contain"
            f" wildcard DNS name {wildcard_dns_name}; it contains {names}."
            f" Wildcard DNS name is needed for SQL support to work."
        )


def validate_image_reader_key(image_reader_creds_file):
    """Checks whether the biOS image reader creds file exists required for fetching
    biOS resources from GCP"""
    Log.info("Checking whether bi(OS) image reader credentials file exists")
    if not os.path.exists(image_reader_creds_file):
        message = f"bi(OS) image reader credentials file {image_reader_creds_file} is missing"
        raise Exception(message)


def install_bios(config):
    Log.info("Installing bi(OS) cluster")

    initialize_ports_file(config)
    setup_connect_aliases(config)
    install_dependencies(config)
    reopen_connections(config)
    retabulate_version_numbers(config)
    clean_hosts(config)
    bios_version = config["images"]["bios"]["image_version"]
    Log.info(f"Starting bi(OS) installation with version {bios_version}")
    setup_jupyterhub(config)
    configure_storage_nodes(config)
    configure_lb_nodes(config)
    set_systemadmin_password(config)
    set_upstream_config(config)
    Log.info("+ + + + Completed installing core components of bi(OS) cluster.")
    initialize_system_schema(config)
    save_host_details(config)
    populate_email_domains(config)
    configure_fluentbit(config)
    configure_dbdozer(config)
    configure_sql(config, config["system_tenant"])
    configure_apps(config, config["system_tenant"])
    configure_logrotate(config)
    create_starter_reports(config)


def cleanup_bios(config):
    Log.info("Cleaning up bi(OS) cluster")

    reopen_connections(config)
    # retabulate_version_numbers(config)
    clean_hosts(config)
    if os.path.exists(PORTS_FILE):
        os.remove(PORTS_FILE)


def setup_jupyterhub(config):
    if config["roles"].get("jupyter_hub"):
        hub_node = config["roles"]["jupyter_hub"][0]
    else:
        config["bios_hub_token"] = config["bios_hub_server"] = ""
        Log.info("No nodes to setup JupyterHub specified/available, skipping it")
        return

    Log.info(f"Setting up Jupyter Hub on node {get_name_and_ip(hub_node)}")
    jupyterhub_container = get_docker_instance(config, hub_node, CONTAINER_T_DEV)
    jupyterhub_users_directory = config["jupyterhub_users_directory"]
    ports_config = load_yaml_file(PORTS_FILE)
    port_num = ports_config["jupyterhub"]

    run_sudo_remote(hub_node, f"mkdir -p {jupyterhub_users_directory}")
    run_sudo_remote(hub_node, f"chown -R $USER:$USER {jupyterhub_users_directory}")

    run_remote_journal(
        hub_node,
        f"docker run --restart unless-stopped"
        f" -dp {port_num}:8000 --name {jupyterhub_container.name}"
        f" -v {jupyterhub_users_directory}:/home"
        f" {jupyterhub_container.image_url}",
        jupyterhub_container.name,
    )

    done = False
    failed_attempts = 0
    max_attempts = 5
    wait_time = 2

    while not done:
        try:
            # Wait for the jupyterhub server to come up.
            time.sleep(wait_time)
            # Get the admin token and save it.
            result = run_remote(
                hub_node, f"docker exec {jupyterhub_container.name} jupyterhub token admin"
            )
            done = True
        except Exception as exception:
            failed_attempts += 1
            Log.debug(
                f"Attempt {failed_attempts} at obtaining jupyterhub admin token failed, "
                f"retrying after {wait_time} seconds "
            )

            if failed_attempts > max_attempts:
                Log.info("JupyterHub unable to create admin token!")
                raise exception

    admin_token = result.stdout.strip()
    Log.debug(f" JupyterHub admin token: {admin_token}")

    config["bios_hub_token"] = admin_token
    config["bios_hub_server"] = hub_node["ip"]


def initialize_ports_file(config):
    """Assigns ports to applications and creates ports.yaml file"""
    # If the ports file already exists, there is currently an installation of bios on this cluster.
    # Do not continue installation because it will destroy all the data in the cluster.
    if os.path.isfile(PORTS_FILE):
        raise RuntimeError(
            f"File {PORTS_FILE} already exists, indicating an existing bios installation."
            f" Not continuing installation to avoid deleting all data in the existing cluster."
            " In order to start over the installation, run 'install_bios.py clean' first."
        )
    port_offset = config["app_ports_offset"]
    ports_config = {
        "jupyterhub": port_offset,
        "highest_port_used": port_offset,
    }
    save_yaml_file(PORTS_FILE, ports_config)


def clean_hosts(config):
    execute_on_hosts(
        clean_on_host,
        "Clean host",
        config["hosts"].values(),
        config,
    )
    run_local(f"rm -rf {LOCAL_JOURNAL_PATH}")
    run_local(f"mkdir -p {LOCAL_JOURNAL_PATH}")


def clean_on_host(index, host, config):
    del index
    Log.debug(f"Cleaning host: {get_name_and_ip(host)}")

    Log.debug(f"Stopping and removing all docker containers on: {get_name_and_ip(host)}")
    names = config["container_name"]
    run_remote(host, f"docker kill $(docker ps -q -f name={names[CONTAINER_T_BIOS]})", [1])
    run_remote(host, f"docker kill $(docker ps -q -f name={names[CONTAINER_T_STORAGE]})", [1])
    run_remote(host, f"docker kill $(docker ps -q -f name={names[CONTAINER_T_DEV]})", [1])
    run_remote(host, f"docker kill $(docker ps -q -f name={names[CONTAINER_T_LOAD]})", [1])
    run_remote(host, f"docker kill $(docker ps -q -f name={names[CONTAINER_T_MAINTAINER]})", [1])
    run_remote(host, f"docker rm $(docker ps -a -q -f name={names[CONTAINER_T_BIOS]})", [1])
    run_remote(host, f"docker rm $(docker ps -a -q -f name={names[CONTAINER_T_STORAGE]})", [1])
    run_remote(host, f"docker rm $(docker ps -a -q -f name={names[CONTAINER_T_DEV]})", [1])
    run_remote(host, f"docker rm $(docker ps -a -q -f name={names[CONTAINER_T_LOAD]})", [1])
    run_remote(host, f"docker rm $(docker ps -a -q -f name={names[CONTAINER_T_MAINTAINER]})", [1])

    Log.debug(f"Removing any resource directories on: {get_name_and_ip(host)}")
    run_sudo_remote(
        host,
        "find "
        + config["isima_base_path"]
        + " -mindepth 1 -maxdepth 1 -not -name lcm -exec rm -rf {} \\;",
        [1],
    )
    run_sudo_remote(host, f"rm -rf {get_log_path(config, 'lb_log_dir')}")
    run_sudo_remote(host, f"rm -rf {get_log_path(config, 'dbdozer_log_dir')}")
    run_sudo_remote(host, f"rm -rf {get_log_path(config, 'load_log_dir')}-*")
    run_sudo_remote(host, f"rm -rf {get_log_path(config, 'integrations_log_dir')}-*")
    run_sudo_remote(host, f"rm -rf {get_log_path(config, 'sql_log_dir')}-*")

    run_remote(host, f"mkdir -p {REMOTE_JOURNAL_PATH}")

    Log.debug(f"Completed cleaning host: {get_name_and_ip(host)}")


def configure_node_logrotate(index, host, none):
    del index, none
    Log.info(f"Copying logrotate file to node {get_name_and_ip(host)}")
    put_file(host, f"{BIOS_CONFIGS_PATH}/bios_logrotate.conf", "/tmp")

    Log.info(f"Configuring logrotate on node {get_name_and_ip(host)}")
    config_file_path = "/etc/logrotate.d/bios_logrotate.conf"
    run_sudo_remote(host, "mkdir -p /etc/cron.hourly")
    # If the file was already moved, it will not be present, so that error is OK.
    run_sudo_remote(host, "mv /etc/cron.daily/logrotate /etc/cron.hourly", [1])
    run_sudo_remote(host, f"mv -f /tmp/bios_logrotate.conf {config_file_path}")
    run_sudo_remote(host, f"chown root:root {config_file_path}")
    run_sudo_remote(host, f"chmod 644 {config_file_path}")
    run_sudo_remote(host, f"logrotate {config_file_path}")


def configure_logrotate(config):
    execute_on_hosts(
        configure_node_logrotate,
        "Configure logrotate for all nodes",
        config["hosts"].values(),
        None,
    )


def configure_storage_nodes(config):
    run_local(f"mkdir -p {CACHE_DIR}")
    run_local(f"rm -rf {LOCAL_RES_PATH_BASE}")
    for sub_role in config["sub_roles"]:
        local_res_path = f"{LOCAL_RES_PATH_BASE}/{sub_role}"
        run_local(f"mkdir -p {local_res_path}")

    storage_nodes = config["roles"]["storage"]
    execute_on_hosts(
        cleanup_and_initialize_local, "Initialize storage hosts", storage_nodes, config
    )

    cluster_name = config["cluster_name"]
    if not os.path.isfile(f"{CACHE_DIR}/{cluster_name}.key.pem"):
        Log.info("Generating DB TLS certificate files")
        # Generate certificates for communication among bios-storage nodes.
        run_local(
            f"{LCM_DIR}/scripts/generate-db-ssl {LOCAL_RES_PATH_BASE}"
            f" {cluster_name} localhost secret"
            f" && cp {LOCAL_RES_PATH_BASE}/{{*.cer,db.*,*.pem}} {CACHE_DIR}"
        )
    else:
        Log.info(f"DB TLS certificates are found in {CACHE_DIR}, will reuse them")
        run_local(f"cp {CACHE_DIR}/{{*.cer,db.*,*.pem}} {LOCAL_RES_PATH_BASE}/")

    execute_on_hosts(initialize_bios_storage, "Start running DB", storage_nodes, config)

    for sub_role in config["sub_roles"]:
        local_res_path = f"{LOCAL_RES_PATH_BASE}/{sub_role}"
        run_local(f"cat {local_res_path}/server*.cert.pem >> {LOCAL_RES_PATH_BASE}/cacerts.pem")

    execute_on_hosts(wait_for_db_up, "Wait for DB to start", storage_nodes, config)
    Log.info("Completed initial starting of bios-storage containers; configuring them...")
    alter_keyspace(storage_nodes[0], config)
    create_mbean_user(storage_nodes[0], config)
    wait_for_db_cluster_formation(storage_nodes[0], len(storage_nodes), config)
    execute_on_hosts(
        repair_compact_rebuild, "Ensure DB replication", storage_nodes, config, parallel=False
    )

    Log.info("Starting bi(OS) on first storage node.")
    host = storage_nodes[0]
    start_bios_container(0, host, config)
    Log.info("Waiting for bi(OS) initialization on first storage node.")
    wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")
    Log.info("First bi(OS) node initialized; waiting for things to settle.")
    time.sleep(15)

    Log.info("Starting bi(OS) on remaining storage nodes.")
    execute_on_hosts(start_bios_container, "Create bios containers", storage_nodes[1:], config)

    execute_on_hosts(configure_bios_on_storage_node, "Configure bi(OS)", storage_nodes, config)
    Log.debug("Completed configuring storage nodes")


def cleanup_and_initialize_local(index, host, config):
    sub_role_index = index % len(config["sub_roles"])
    sub_role = config["sub_roles"][sub_role_index]
    host_str = get_name_and_ip(host)
    Log.info(f"Cleaning up storage node {host_str}")
    Log.debug("Removing any old instances of containers if present")
    container_bios = config["container_name"][CONTAINER_T_BIOS]
    container_bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    run_remote(host, f"docker stop {container_bios} || true")
    run_remote(host, f"docker rm {container_bios} || true")
    run_remote(host, f"docker stop {container_bios_storage} || true")
    run_remote(host, f"docker rm {container_bios_storage} || true")

    # If the logs and/or data volumes have not been mounted, format and mount them now.
    mountpoint = config["logs_dir"]
    result = run_remote(host, f"find {mountpoint} -maxdepth 0 -type d | wc -l")
    logs_dir_count = int(result.stdout.strip())
    if logs_dir_count == 0:
        volume = config["logs_volume"]
        if volume == "ignore":
            raise RuntimeError(
                f"Neither logs directory {mountpoint} is present "
                f"nor property 'logs_volume' is defined in cluster_config.yaml"
            )
        volume_mount_options = "defaults"
        if config["logs_volume_turn_on_discard"]:
            volume_mount_options += ",discard"
        Log.info(f"Formatting and mounting logs volume {volume} to {mountpoint} on {host_str}")
        cmd = create_logs_volume_init_command(volume, mountpoint, volume_mount_options)
        run_remote(host, cmd)

    if host["data_dir_count"] == 0 or (
        config["data_volumes"] and host["data_dir_count"] != len(config["data_volumes"])
    ):
        if not config["data_volumes"]:
            raise RuntimeError(
                f"Neither data directories {config['data_dir_prefix']}* are present "
                f"nor property 'data_volumes' are defined in cluster_config.yaml"
            )
        volume_mount_options = "defaults"
        if config["data_volumes_turn_on_discard"]:
            volume_mount_options += ",discard"
        Log.info(
            f"Formatting and mounting data volumes {config['data_volumes']} "
            f"to {config['data_dir_prefix']}* on {host_str}"
        )
        cmd = create_data_volume_init_command(
            config["data_volumes"], config["data_dir_prefix"], volume_mount_options
        )
        run_remote(host, cmd)
        host["data_dir_count"] = len(config["data_volumes"])
        host_data_file_directories = config.setdefault("host_data_file_directories", {})
        host_data_file_directories[host["ip"]] = [
            f"{config['data_dir_prefix']}{dir_index + 1}"
            for dir_index in range(host["data_dir_count"])
        ]

    if sub_role_index == index:
        Log.info(f"Setting up local files for nodes of type {sub_role}")
        create_sub_role_config_files(config, host, sub_role)


def create_sub_role_config_files(config, host, sub_role):
    # Create a local directory to hold resource files that need to be updated.
    local_res_path = f"{LOCAL_RES_PATH_BASE}/{sub_role}"

    # Copy resource files into this local directory and update them.
    Log.debug(f"Copying and updating resource files into local directory: {local_res_path}")
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db-dc.properties {local_res_path}/")
    file = f"{local_res_path}/db-dc.properties"
    replace_line_re("DC_NAME", f"dc_{sub_role}", file)

    # db-server.options
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db-server.options {local_res_path}/")
    file = f"{local_res_path}/db-server.options"
    replace_line_re("BIOS_STORAGE_CPUS", f"{host['bios_storage_cpus']}", file)
    replace_line_re("BIOS_STORAGE_HEAP_SIZE", f"{host['bios_storage_heap_size']}G", file)

    # db11-server.options
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db11-server.options {local_res_path}/")
    file = f"{local_res_path}/db11-server.options"
    replace_line_re("GC_THREADS", f"{host['gc_threads']}", file)

    # db-clients.options
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db-clients.options {local_res_path}/")

    # db.yaml
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db.yaml {local_res_path}/")
    file = f"{local_res_path}/db.yaml"
    data_file_directories = str.join(
        "",
        [
            f"\n    - /var/lib/db/data{dir_number}"
            for dir_number in get_db_data_dir_numbers(host, config)
        ],
    )
    replace_line_re("DATA_FILE_DIRECTORIES", f"{data_file_directories}", file)
    replace_line_re("DB_PORT", config["db_port"], file)
    replace_line_re("RPC_PORT", config["rpc_port"], file)
    replace_line_re("NON_SECURE_STORAGE_PORT", config["storage_port"], file)
    replace_line_re("SSL_STORAGE_PORT", config["ssl_storage_port"], file)

    # db.env.sh
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/db.env.sh {local_res_path}/")
    file = f"{local_res_path}/db.env.sh"
    replace_line_re("DB_JMX_PORT", config["db_jmx_port"], file)

    # create-mbean-user.cql
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/create-mbean-user.cql {local_res_path}/")
    file = f"{local_res_path}/create-mbean-user.cql"
    replace_line("${DB_JMX_USER}", config["db_jmx_user"], file)
    replace_line("${DB_JMX_PASSWORD}", config["db_jmx_password"], file)

    # jmxremote.password
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/jmxremote.password {local_res_path}/")
    file = f"{local_res_path}/jmxremote.password"
    replace_line("DB_JMX_USER", config["db_jmx_user"], file)
    replace_line("DB_JMX_PASSWORD", config["db_jmx_password"], file)

    # server.options
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/server.options {local_res_path}/")
    file = f"{local_res_path}/server.options"
    if config["bios_hub_token"]:
        replace_line_re("JUPYTER_HUB_ADMIN_TOKEN", f"{config['bios_hub_token']}", file)
    replace_line_re("BIOS_PORT", f"{config['https_port']}", file)
    port = f":{config['lb_https_port']}" if config["lb_https_port"] == 443 else ""
    replace_line_re(":LB_HTTPS_PORT", port, file)
    replace_line_re("CLUSTER_DNS_NAME", f"{config['cluster_dns_name']}", file)
    replace_line_re("LB_HTTPS_PORT", config["lb_https_port"], file)
    replace_line_re("DB_PORT", config["db_port"], file)
    replace_line_re("DB_USER", config["db_user"], file)
    replace_line_re("DB_PASSWORD", config["db_password"], file)
    replace_line_re("XMLRPC_USER", config["xmlrpc_user"], file)
    replace_line_re("XMLRPC_PASSWORD", config["xmlrpc_password"], file)
    replace_line("AUTH_TOKEN_SECRET", config["auth_token_secret"], file)
    replace_line("RESET_PASSWORD_TOKEN_SECRET", config["reset_password_token_secret"], file)
    replace_line("APPROVAL_TOKEN_SECRET", config["approval_token_secret"], file)
    replace_line(
        "EMAIL_VERIFICATION_TOKEN_SECRET", config["email_verification_token_secret"], file
    )
    replace_line(
        "SUBSCRIPTION_FINALIZATION_TOKEN_SECRET",
        config["subscription_finalization_token_secret"],
        file,
    )

    # test specific config
    if os.path.isfile(f"{BIOS_CONFIGS_PATH}/initial_test_users.json"):
        run_local(
            f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/initial_test_users.json {local_res_path}/"
        )
        run_local(
            "echo 'io.isima.bios.initialUsersFile=/opt/bios/configuration/initial_test_users.json'"
            f" >> {file}"
        )
        run_local(f"echo 'io.isima.bios.test.enabled=true' >> {file}")
        run_local(f"echo 'io.isima.bios.test.signup.enabled=true' >> {file}")

        lcm_host = config["roles"]["lcm"][0] if config["roles"]["lcm"] else {}
        lcm_ip = lcm_host.get("ip")
        if lcm_ip:
            run_local(f"echo 'io.isima.bios.mail.secureConnection.disabled=true' >> {file}")
            run_local(f"echo 'io.isima.bios.mail.host={lcm_ip}' >> {file}")
            run_local(f"echo 'io.isima.bios.mail.nonsecureport=1025' >> {file}")

    # email options
    try:
        key = "aws_ses_username"
        replace_line_re("AWS_SES_USERNAME", f"{config[key]}", file)
        key = "aws_ses_password"
        replace_line_re("AWS_SES_PASSWORD", f"{config[key]}", file)
        key = "aws_ses_from_address"
        replace_line_re("AWS_SES_FROM_ADDRESS", f"{config[key]}", file)
        key = "aws_ses_host"
        replace_line_re("AWS_SES_HOST", f"{config[key]}", file)
        key = "approval_admin_email"
        replace_line_re("APPROVAL_ADMIN_EMAIL", f"{config[key]}", file)
    except KeyError:
        Log.warn(
            f"Property '{key}' is missing in cluster_config.yaml."
            " Unable to setup email capability for online signup"
        )

    db_dcs = [
        f"dc_{sub_role}:{len(config['sub_role_servers'][sub_role])}"
        for sub_role in config["sub_roles"]
    ]
    db_dcs_string = ",".join(db_dcs)
    replace_line_re("DB_DATA_CENTERS", db_dcs_string, file)
    if sub_role == "rollup":
        replace_line_re("ROLLUP_ENABLED", "true", file)
    else:
        replace_line_re("ROLLUP_ENABLED", "false", file)

    # cqlshrc
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/cqlshrc {local_res_path}/")
    file = f"{local_res_path}/cqlshrc"
    replace_line_re("CLUSTER_NAME", f"{config['cluster_name']}", file)
    replace_line_re("DB_PORT", config["db_port"], file)

    # Modify the commitlog strategy only on signal nodes.
    if sub_role == "signal":
        replace_line_re("^commitlog_sync:", "# commitlog_sync:", file)
        replace_line_re(
            "^commitlog_sync_batch_window_in_ms:", "# commitlog_sync_batch_window_in_ms:", file
        )
        replace_line_re("^#.*commitlog_sync: periodic", "commitlog_sync: periodic", file)
        replace_line_re(
            "#.*commitlog_sync_period_in_ms:.*", "commitlog_sync_period_in_ms: 20", file
        )


def initialize_bios_storage(index, host, config):
    sub_role_index = index % len(config["sub_roles"])
    sub_role = config["sub_roles"][sub_role_index]
    Log.info(f"Configuring storage node {get_name_and_ip(host)} as node type {sub_role}")
    initialize_storage_files(index, host, config, sub_role)
    start_bios_storage(config, host)


def initialize_storage_files(index, host, config, sub_role):
    server_resources_dir = get_resources_path(config, "server_resources_dir")
    db_resources_dir = get_resources_path(config, "db_resources_dir")
    local_res_path = f"{LOCAL_RES_PATH_BASE}/{sub_role}"

    # Generate self-signed certificates for internal communication among bios nodes.
    run_local(
        f"{LCM_DIR}/scripts/generate-self-signed-certificate"
        f" {local_res_path}/server{index} {host['ip']}"
    )

    # Initialize server-specific config files.
    file = f"{local_res_path}/nghttpx.conf.{index}"
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/nghttpx.conf {file}")
    replace_line_re("BIOS_HOST", host["ip"], file)
    replace_line_re("BIOS_PORT", str(config["https_port"]), file)
    replace_line_re("NGHTTPX_PORT", str(config["nghttpx_port"]), file)

    file = f"{local_res_path}/bios-jvm.options.{index}"
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/bios-jvm.options {file}")
    replace_line_re("SERVER_HEAP_SIZE", f"{host['bios_heap_size']}G", file)

    # Create a remote resources directory and copy config files into it.
    run_sudo_remote(host, f"rm -rf {server_resources_dir}")
    run_sudo_remote(host, f"mkdir -p {server_resources_dir}/standard")
    run_sudo_remote(host, f"chown -R $USER:$USER {server_resources_dir}/..")
    run_sudo_remote(host, f"rm -rf {db_resources_dir}")
    run_sudo_remote(host, f"mkdir -p {db_resources_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {db_resources_dir}/..")

    put_file(host, f"{local_res_path}/server.options", server_resources_dir)
    if os.path.isfile(f"{local_res_path}/initial_test_users.json"):
        put_file(host, f"{local_res_path}/initial_test_users.json", server_resources_dir)
    put_file(host, f"{local_res_path}/server{index}.p12", f"{server_resources_dir}/server.p12")
    put_file(
        host, f"{local_res_path}/server{index}.cert.pem", f"{server_resources_dir}/server.cert.pem"
    )
    put_file(
        host, f"{local_res_path}/server{index}.key.pem", f"{server_resources_dir}/server.key.pem"
    )
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.pks12.keystore", server_resources_dir)
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.truststore", server_resources_dir)
    put_file(host, f"{BIOS_CONFIGS_PATH}/bios_sysctl.conf", f"{server_resources_dir}/standard")
    put_file(host, f"{BIOS_CONFIGS_PATH}/bios_limits.conf", f"{server_resources_dir}/standard")
    put_file(host, f"{BIOS_CONFIGS_PATH}/log4j2.xml", server_resources_dir)
    put_file(
        host, f"{local_res_path}/nghttpx.conf.{index}", f"{server_resources_dir}/nghttpx.conf"
    )
    put_file(
        host,
        f"{local_res_path}/bios-jvm.options.{index}",
        f"{server_resources_dir}/bios-jvm.options",
    )

    put_file(host, f"{local_res_path}/cqlshrc", db_resources_dir)
    put_file(host, f"{local_res_path}/db-dc.properties", db_resources_dir)
    put_file(host, f"{local_res_path}/db-server.options", db_resources_dir)
    put_file(host, f"{local_res_path}/db11-server.options", db_resources_dir)
    put_file(host, f"{local_res_path}/db-clients.options", db_resources_dir)
    put_file(host, f"{local_res_path}/db.yaml", db_resources_dir)
    put_file(host, f"{local_res_path}/db.env.sh", db_resources_dir)
    put_file(host, f"{local_res_path}/create-mbean-user.cql", db_resources_dir)
    put_file(host, f"{local_res_path}/jmxremote.password", db_resources_dir)
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.pks12.keystore", db_resources_dir)
    put_file(host, f"{LOCAL_RES_PATH_BASE}/db.truststore", db_resources_dir)
    put_file(host, f"{BIOS_CONFIGS_PATH}/alter-keyspace.cql", db_resources_dir)
    put_file(host, f"{LOCAL_RES_PATH_BASE}/{config['cluster_name']}.cer.pem", db_resources_dir)
    put_file(host, f"{LOCAL_RES_PATH_BASE}/{config['cluster_name']}.key.pem", db_resources_dir)

    run_remote(host, f"touch {server_resources_dir}/{BIOS_RESOURCES_COMPLETION_MARKER}")
    run_remote(host, f"touch {db_resources_dir}/{BIOS_RESOURCES_COMPLETION_MARKER}")

    # Create directories for various places used by bios-storage and bios.
    run_sudo_remote(host, f"rm -rf {config['logs_dir']}/*")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/data/commitlog")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/db/heapdump")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/data/hints")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/data/saved_caches")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/log/db")
    run_sudo_remote(host, f"mkdir -p {config['logs_dir']}/log/server")
    # Create convenience symbolic links
    db_log_dir = get_log_path(config, "db_log_dir")
    run_sudo_remote(host, f"sudo mkdir -p {os.path.dirname(db_log_dir)}")
    run_sudo_remote(host, f"sudo chown -R root:syslog {os.path.dirname(db_log_dir)}")
    run_sudo_remote(host, f"sudo chmod 777 {os.path.dirname(db_log_dir)}")
    run_sudo_remote(host, f"sudo ln -sfT {config['logs_dir']}/log/db {db_log_dir}")
    server_log_dir = get_log_path(config, "server_log_dir")
    run_sudo_remote(host, f"sudo ln -sfT {config['logs_dir']}/log/server {server_log_dir}")

    for dir_number in get_db_data_dir_numbers(host, config):
        run_sudo_remote(host, f"rm -rf {config['data_dir_prefix']}{dir_number}/*")

    # Update system files.
    run_sudo_remote(
        host,
        f"cat {server_resources_dir}/standard/bios_sysctl.conf "
        "| sudo tee -a /etc/sysctl.conf > /dev/null",
    )
    run_sudo_remote(host, "sysctl -p")
    run_sudo_remote(
        host,
        f"cat {server_resources_dir}/standard/bios_limits.conf "
        "| sudo tee -a /etc/security/limits.conf > /dev/null",
    )


def start_bios_storage(config, host):
    bios_storage = config["container_name"].get(CONTAINER_T_STORAGE)
    image_tag = config["images"]["bios-storage"]["tag"]
    db_log_dir = get_log_path(config, "db_log_dir")
    add_logs_alias(host, "logs-bios-storage", f"{db_log_dir}/system.log")
    add_logs_alias(host, "logs-bios-storage-debug", f"{db_log_dir}/debug.log")
    to_bash_profile(
        host,
        'alias logs-bios-storage-all="tail -F /var/log/db/system.log /var/log/db/debug.log"',
    )
    db_jmx_user = config["db_jmx_user"]
    db_jmx_password = config["db_jmx_password"]
    to_bash_profile(
        host,
        f'alias nodetool-status="docker exec {bios_storage} /opt/db/bin/nodetool'
        f' --ssl -u {db_jmx_password} -pw {db_jmx_password} status"',
    )
    to_bash_profile(
        host,
        f"alias nodetool=\"echo -e '\\'\\\\nRun:\\\\n    docker exec -it {bios_storage} bash\\\\n"
        f"    nodetool --ssl -u {db_jmx_user} -pw {db_jmx_password} status\\\\n\\''\"",
    )
    to_bash_profile(
        host,
        f"alias cqlsh=\"echo -e '\\'\\\\nRun:\\\\n    docker exec -it {bios_storage} bash\\\\n"
        f"    cqlsh --ssl -u {config['db_user']} -p {config['db_password']}"
        " --cqlshrc=/var/ext_resources/cqlshrc\\\\n\\''\"",
    )

    # Deploy bios-storage container.
    cpuset = if_not_auto(config["db_cpuset"], f"0-{host['bios_storage_cpus'] - 1}")
    memory = if_not_auto(config["db_memory"], f"{host['bios_storage_memory']}g")
    resources_dir = get_resources_path(config, "db_resources_dir")
    cmd = (
        f"docker run --name {bios_storage} -d "
        f" --restart unless-stopped "
        f" --cap-add=IPC_LOCK "
        f" --ulimit nofile=1000000:1000000 --ulimit nproc=32768 --ulimit memlock=-1:-1 "
        f" --memory={memory} "
        f" --cpuset-cpus={cpuset} "
        f" --network host "
        f" -e DB_YAML='/var/ext_resources/db.yaml' "
        f" -e DB_KEYSTORE='/var/ext_resources/db.pks12.keystore' "
        f" -e DB_TRUSTSTORE='/var/ext_resources/db.truststore' "
        f" -e DB_JVM_SERVER_OPTIONS='/var/ext_resources/db-server.options' "
        f" -e DB_JVM11_SERVER_OPTIONS='/var/ext_resources/db11-server.options' "
        f" -e DB_JVM_CLIENTS_OPTIONS='/var/ext_resources/db-clients.options' "
        f" -e DB_ENV='/var/ext_resources/db.env.sh' "
        f" -e DB_RACKDC_PROPERTIES='/var/ext_resources/db-dc.properties' "
        f" -e BIOS_SEEDS={config['bios_seeds']} "
        f" -e DB_CLUSTER_NAME={config['cluster_name']} "
        f" -e DB_ENDPOINT_SNITCH={config['db_endpoint_snitch']} "
        f" -e DB_BROADCAST_ADDRESS={host['ip']} "
        f" -e DB_BROADCAST_RPC_ADDRESS={host['ip']} "
        f" -e JAVA_TOOL_OPTIONS='-Dcom.sun.jndi.rmiURLParsing=legacy' "
        f" -v {resources_dir}:/var/ext_resources "
        f" -v {config['logs_dir']}/data/commitlog:/var/lib/db/commitlog "
        f" -v {config['logs_dir']}/db/heapdump:/var/lib/db/heapdump "
        f" -v {config['logs_dir']}/data/hints:/var/lib/db/hints "
        f" -v {config['logs_dir']}/data/saved_caches:/var/lib/db/saved_caches "
        f" -v {config['logs_dir']}/log/db:/opt/db/logs "
    )
    for dir_number in get_db_data_dir_numbers(host, config):
        cmd += f" -v {config['data_dir_prefix']}{dir_number}:/var/lib/db/data{dir_number} "
    cmd += f" {image_tag}"

    Log.debug("Starting a new container for bios-storage")
    run_remote_journal(host, cmd, bios_storage)
    run_remote(host, f"docker cp {resources_dir}/jmxremote.password {bios_storage}:/opt/db/conf/")
    run_remote(host, f"docker exec {bios_storage} cp /var/ext_resources/cqlshrc /root/.cassandra/")


def start_bios_container(index, host, config):
    del index
    server_log_dir = get_log_path(config, "server_log_dir")
    add_logs_alias(host, "logs-bios", f"{server_log_dir}/server.log")
    add_logs_alias(host, "logs-nghttpx-access", f"{server_log_dir}/nghttpx-access.log")
    add_logs_alias(host, "logs-nghttpx-errors", f"{server_log_dir}/nghttpx-errors.log")
    to_bash_profile(
        host,
        f'alias logs-bios-all="tail -F {server_log_dir}/server.log '
        f'{server_log_dir}/nghttpx-access.log {server_log_dir}/nghttpx-errors.log"',
    )
    put_file(
        host,
        f"{LOCAL_RES_PATH_BASE}/cacerts.pem",
        get_resources_path(config, "server_resources_dir"),
    )
    run_bios_on_host(host, config, first_install=True)


def alter_keyspace(host, config):
    bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    done = False
    tries = 0
    while not done:
        try:
            run_remote(
                host,
                f"docker exec {bios_storage} /opt/db/bin/cqlsh --ssl -u cassandra -p cassandra"
                " --cqlshrc /var/ext_resources/cqlshrc -f /var/ext_resources/alter-keyspace.cql",
            )
            done = True
        except Exception as exception:
            if tries >= 36:
                raise RuntimeError(
                    f"bios-storage: could not alter keyspace after waiting for 5 * {tries} seconds."
                ) from exception
            time.sleep(5)
            tries += 1


def create_mbean_user(host, config):
    bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    done = False
    tries = 0
    while not done:
        try:
            run_remote(
                host,
                f"docker exec {bios_storage} /opt/db/bin/cqlsh --ssl -u cassandra -p cassandra"
                " --cqlshrc /var/ext_resources/cqlshrc"
                " -f /var/ext_resources/create-mbean-user.cql",
            )
            done = True
        except Exception as exception:
            if tries >= 36:
                raise RuntimeError(
                    f"{bios_storage}: could not create user after waiting for 5 * {tries} seconds."
                ) from exception
            time.sleep(5)
            tries += 1


def repair_compact_rebuild(index, host, config):
    del index
    bios_storage = config["container_name"][CONTAINER_T_STORAGE]
    db_jmx_user = config["db_jmx_user"]
    db_jmx_password = config["db_jmx_password"]
    run_remote(
        host,
        f"docker exec {bios_storage} /opt/db/bin/nodetool --ssl -u {db_jmx_user}"
        f" -pw {db_jmx_password} repair >/dev/null 2>&1",
    )
    run_remote(
        host,
        f"docker exec {bios_storage} /opt/db/bin/nodetool --ssl -u {db_jmx_user}"
        f" -pw {db_jmx_password} compact >/dev/null 2>&1",
    )
    run_remote(
        host,
        f"docker exec {bios_storage} /opt/db/bin/nodetool --ssl -u {db_jmx_user}"
        f" -pw {db_jmx_password} rebuild >/dev/null 2>&1",
    )


def configure_lb_nodes(config):
    Log.info("Configuring load balancer vms")
    # Prepare bioslb resources.
    run_local(f"mkdir -p {LOCAL_RES_PATH_BASE}")
    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/load-balancer.conf {LOCAL_RES_PATH_BASE}/"
    )
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/block_ip.conf {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/load-balancer.conf"
    # General: main upstreams are analysis nodes and backup upstreams are rollup nodes.
    # Inserts: main upstreams are signal nodes and backup upstreams are analysis nodes.
    servers = config["sub_role_servers"]

    delimiter = "\n    "

    analysis_unsecure = delimiter.join(
        {f"server {node}:{config['http_port']};" for node in servers["analysis"]}
    )

    rollup_unsecure_backup = delimiter.join(
        {f"server {node}:{config['http_port']} backup;" for node in servers["rollup"]}
    )

    http3_enabled = config["http3_enabled"]
    storage_upstream_port = config["http3_port" if http3_enabled else "nghttpx_port"]
    signal_secure = delimiter.join(
        {f"server {node}:{storage_upstream_port};" for node in servers["signal"]}
    )

    analysis_secure_backup = delimiter.join(
        {f"server {node}:{storage_upstream_port} backup;" for node in servers["analysis"]}
    )

    analysis_secure = delimiter.join(
        {f"server {node}:{storage_upstream_port};" for node in servers["analysis"]}
    )

    rollup_secure_backup = delimiter.join(
        {f"server {node}:{storage_upstream_port} backup;" for node in servers["rollup"]}
    )

    replace_line_re(
        "MAIN_UPSTREAM_UNSECURE_SERVERS",
        analysis_unsecure,
        file,
    )
    replace_line_re(
        "BACKUP_UPSTREAM_UNSECURE_SERVERS",
        rollup_unsecure_backup,
        file,
    )
    replace_line_re(
        "MAIN_UPSTREAM_BIOS_INSERT_SERVERS",
        signal_secure,
        file,
    )
    replace_line_re(
        "BACKUP_UPSTREAM_BIOS_INSERT_SERVERS",
        analysis_secure_backup,
        file,
    )
    replace_line_re("MAIN_UPSTREAM_BIOS_SERVERS", analysis_secure, file)
    replace_line_re(
        "BACKUP_UPSTREAM_BIOS_SERVERS",
        rollup_secure_backup,
        file,
    )
    if http3_enabled:
        replace_line_re(
            "# BIOS_STORAGE_UPSTREAM_ANCHOR",
            """keepalive 32;
    keepalive_requests 100000;
    keepalive_timeout 600s;""",
            file,
        )
        replace_line_re(
            "# BIOS_STORAGE_PROXY_ANCHOR",
            """proxy_http_version 3;
        proxy_http3_max_concurrent_streams 8192;
        proxy_socket_keepalive on;
        proxy_ssl_trusted_certificate /var/ext_resources/cacerts.pem;""",
            file,
        )

    replace_line_re("LB_HTTP_PORT", config["lb_http_port"], file)
    replace_line_re("LB_HTTPS_PORT", config["lb_https_port"], file)
    replace_line_re("CLUSTER_DNS_NAME", config["cluster_dns_name"], file)

    if config["bios_hub_server"]:
        bios_hub_upstream_config = f"""BIOS_HUB_UPSTREAM_ANCHOR
upstream bios_hub_server {{
    hash $remote_addr;
    server {config["bios_hub_server"]}:11000;
}}
"""
        replace_line_re("BIOS_HUB_UPSTREAM_ANCHOR", bios_hub_upstream_config, file)

        bios_hub_locations = """BIOS_HUB_LOCATIONS_ANCHOR
    location ~ ^/user/ {
        proxy_pass http://bios_hub_server;
        proxy_read_timeout 300s;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        access_log /var/log/nginx/bios_jhub.log upstream_info;
    }
    location /hub/api {
        proxy_pass http://bios_hub_server;
        proxy_read_timeout 300s;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        access_log /var/log/nginx/bios_jhub.log upstream_info;
    }
"""
        replace_line_re("BIOS_HUB_LOCATIONS_ANCHOR", bios_hub_locations, file)

    bioslb_nodes = config["roles"]["lb"]
    execute_on_hosts(configure_lb, "Initialize bioslb", bioslb_nodes, config)
    Log.debug("Completed configuring load balancer nodes")


def configure_lb(index, host, config):
    del index
    Log.debug(f"Configuring load balancer node: {get_name_and_ip(host)}")

    remote_res_path = get_resources_path(config, "lb_resources_dir")
    static_contents_path = f"{remote_res_path}/static_contents"

    # Create a remote resources directory and copy config files into it.
    run_sudo_remote(host, f"rm -rf {remote_res_path}")
    run_sudo_remote(host, f"mkdir -p {remote_res_path}/conf.d")
    run_sudo_remote(host, f"mkdir -p {remote_res_path}/cache")
    run_sudo_remote(host, f"mkdir -p {remote_res_path}/static_contents")
    run_sudo_remote(host, f"mkdir -p {remote_res_path}/static_contents.backups")
    run_sudo_remote(host, f"chmod -R a+w {remote_res_path}")
    run_sudo_remote(host, f"chown -R $USER:$USER {remote_res_path}/..")
    lb_log_dir = get_log_path(config, "lb_log_dir")
    run_sudo_remote(host, f"rm -rf {lb_log_dir}")
    run_sudo_remote(host, f"mkdir -p {lb_log_dir}")
    run_sudo_remote(host, f"chmod a+w {lb_log_dir}")
    put_file(host, CERT_FILE, remote_res_path)
    put_file(host, KEY_FILE, remote_res_path)
    key_filename = KEY_FILE.rsplit("/", maxsplit=1)[-1]
    run_remote(host, f"chmod 600 {remote_res_path}/{key_filename}")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/load-balancer.conf", f"{remote_res_path}/conf.d/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/block_ip.conf", f"{remote_res_path}/conf.d/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/cacerts.pem", remote_res_path)

    add_logs_alias(host, "logs-bioslb-general", f"{lb_log_dir}/bios.log")
    add_logs_alias(host, "logs-bioslb-error", f"{lb_log_dir}/error.log")
    add_logs_alias(host, "logs-bioslb-inserts", f"{lb_log_dir}/bios_inserts.log")
    add_logs_alias(host, "logs-bioslb-auth", f"{lb_log_dir}/bios_auth.log")
    add_logs_alias(host, "logs-bioslb-reports", f"{lb_log_dir}/bios_reports.log")
    add_logs_alias(host, "logs-bioslb-docs", f"{lb_log_dir}/bios_docs.log")
    add_logs_alias(host, "logs-bioslb-jhub", f"{lb_log_dir}/bios_jhub.log")
    to_bash_profile(
        host,
        f'alias logs-bioslb-all="tail -F {lb_log_dir}/bios.log {lb_log_dir}/error.log '
        f"{lb_log_dir}/bios_inserts.log {lb_log_dir}/bios_auth.log "
        f"{lb_log_dir}/bios_reports.log {lb_log_dir}/bios_docs.log "
        f'{lb_log_dir}/bios_jhub.log"',
    )

    # Deploy bioslb container.
    container_name = config["container_name"][CONTAINER_T_LB]
    image_tag = config["images"]["bioslb"]["tag"]

    cmd = (
        f"docker run --name {container_name} -d"
        f" --restart unless-stopped"
        f" --network host --privileged"
        f" -v {lb_log_dir}:/var/log/nginx"
        f" -v {remote_res_path}:/var/ext_resources"
        f" -v {static_contents_path}:/var/www/tf/ss"
        f" {image_tag}"
    )

    Log.debug(
        "Removing any old instance of the container if present and starting"
        " a container for bioslb"
    )
    run_remote(host, f"docker stop {container_name} || true")
    run_remote(host, f"docker rm {container_name} || true")
    run_remote_journal(host, cmd, "bioslb")

    # Install the UI
    ui_filename = config["ui_filename"]
    if ui_filename:
        Log.info("Installing UI")
        download_file(config, ui_filename, host, "/tmp")
        run_remote(
            host,
            f"tar -xzf /tmp/{ui_filename} --directory={static_contents_path}/",
        )
    else:
        Log.error(
            "Property 'ui_filename' is not specified in cluster_config.yaml."
            " Skipping to install the UI."
        )

    # Install the docs
    docs_filename = config["docs_filename"]
    if docs_filename:
        Log.info("Installing docs")
        download_file(config, docs_filename, host, "/tmp")
        run_remote(
            host,
            f"tar -xzf /tmp/{docs_filename} --directory={static_contents_path}",
        )
    else:
        Log.error(
            "Property 'docs_filename' is not specified in cluster_config.yaml."
            " Skipping to install the docs."
        )


def set_systemadmin_password(config):
    Log.info(
        f"Using bi(OS) Python SDK to login to cluster using DNS name {config['cluster_dns_name']}"
    )
    try:
        session = create_bios_session(config, "systemadmin@isima.io", "systemadmin")
    except Exception as err:
        Log.error(
            f"Could not login to cluster; verify that firewall allows access to TCP port"
            f" {config['lb_https_port']} on machines pointed to by {config['cluster_dns_name']}"
        )
        Log.debug(str(err))
        return

    Log.info("Setting system admin password")
    session.change_password("systemadmin", config["systemadmin_password"], "systemadmin@isima.io")
    Log.info("Logging in as system admin with new password")
    create_bios_session_system(config)


def set_upstream_config(config):
    Log.info("Setting up upstream config for bi(OS) clients.")
    session = create_bios_session_system(config)
    servers = config["sub_role_servers"]

    role_set = {sub_roles: "" for sub_roles in config["sub_roles"]}
    delimiter = ", "

    for sub_role in role_set.keys():
        role_set[sub_role] = delimiter.join(
            {f"\"https://{node_ip}:{config['https_port']}\"" for node_ip in servers[sub_role]}
        )

    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/upstream_config.json {LOCAL_RES_PATH_BASE}/"
    )
    file = f"{LOCAL_RES_PATH_BASE}/upstream_config.json"
    replace_line_re("SIGNAL", role_set["signal"], file)
    replace_line_re("ANALYSIS", role_set["analysis"], file)
    replace_line_re("ROLLUP", role_set["rollup"], file)
    upstream_config = ""
    with open(file, encoding="UTF-8") as upstream_config_file:
        upstream_config = upstream_config_file.read()
    session.set_property("upstream", upstream_config)


def main():
    if len(sys.argv) < 2:
        _usage()
    else:
        if len(sys.argv) >= 3 and sys.argv[2] == "verbose":
            Log.set_verbose_output(True)

        sub_command = sys.argv[1]
        sub_commands = {"validate", "install", "clean", "status"}
        if sub_command not in sub_commands:
            if sub_command != "help":
                Log.error(f"Unknown subcommand: {sub_command}")
            _usage()

        config = initialize_lcm()
        validate_cert_file(config, CERT_FILE)
        # validate_image_reader_key(CREDS_FILE)

        if sub_command == "validate":
            Log.marker("Completed validating connections to all hosts!")
        elif sub_command == "install":
            install_bios(config)
            Log.marker("Completed installing a fresh bi(OS) cluster!")
        elif sub_command == "clean":
            cleanup_bios(config)
            Log.marker("Completed cleaning up bi(OS) cluster!")
        elif sub_command == "status":
            report_bios_status(config)
        else:
            _usage()


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
