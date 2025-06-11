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

import copy
import json
import random
import re
import socket
import string
import time
from functools import partial
from typing import Tuple

import bios
from lib.common_with_bios import create_bios_session_system
from lib.constants import (
    BIOS_APPS_LOCATIONS_ANCHOR,
    BIOS_APPS_UPSTREAMS_ANCHOR,
    BIOS_CONFIGS_PATH,
    CERT_FILE,
    CONTAINER_T_BIOS,
    CONTAINER_T_INTEGRATIONS,
    CONTAINER_T_LB,
    CONTAINER_T_LOAD,
    CONTAINER_T_SQL,
    DISCOVERY_URI,
    HTTP_PORT,
    HTTPS_PORT,
    IS_COORDINATOR,
    IS_COORDINATOR_ALSO_WORKER,
    KEY_FILE,
    LOCAL_RES_PATH_BASE,
    NODE_ENVIRONMENT,
    NODE_ID,
    PORTS_FILE,
    SERVER_CERT_FILE,
    SHARED_SECRET,
    TRINO_FOLDER,
    WEB_UI_ENABLED,
)

from .common import (
    add_logs_alias,
    deep_merge_dictionaries,
    execute_on_hosts,
    get_file,
    get_log_path,
    get_name_and_ip,
    get_resources_path,
    load_yaml_file,
    put_file,
    replace_line,
    run_local,
    run_remote,
    run_remote_journal,
    run_sudo_remote,
    save_yaml_file,
    to_bash_profile,
    wait_for_bios_up,
)
from .docker_instance import get_docker_instance
from .log import Log


def allocate_port(tenant_name: str, purpose: str) -> Tuple[int, bool]:
    """Allocates a port for a service.

    If the port for the purpose is assigned already, the method reuses the

    Args:
        tenant_name (str): Tenant name
        purpose (str): Purpose of the allocating port
    Returns: Tuple[int, bool]: Tuple of port number and flag that indicates whether the port is
        newly assigned
    """
    ports_config = load_yaml_file(PORTS_FILE)
    new_port = ports_config["highest_port_used"] + 1
    ports_config["highest_port_used"] = new_port
    if tenant_name not in ports_config:
        ports_config[tenant_name] = {}
    if purpose in ports_config[tenant_name]:
        Log.warn(
            f"A port was already allocated for tenant {tenant_name} for purpose {purpose}:"
            f" port {ports_config[tenant_name][purpose]}"
        )
        return ports_config[tenant_name][purpose], False
    ports_config[tenant_name][purpose] = new_port
    save_yaml_file(PORTS_FILE, ports_config)
    return new_port, True


def get_tenant_user(tenant, app_type):
    tenant_name = tenant["tenant_name"]
    user = tenant[app_type]["user"]
    password = tenant[app_type]["password"]
    return tenant_name, user, password


def install_trino_client():
    run_local(f"mkdir -p {TRINO_FOLDER}")
    run_local(
        f"wget -N "
        f"https://repo.maven.apache.org/maven2/io/trino/trino-cli/374/trino-cli-374-executable.jar"
        f" -O {TRINO_FOLDER}/trino-cli"
    )
    run_local(f"chmod +x {TRINO_FOLDER}/trino-cli")


def cleanup_old_container_if_present(host, tenant_name, bios_sql_container, config):
    Log.debug(
        f"Removing any old instance of the container if present and starting a container for"
        f" {bios_sql_container.name}"
    )
    run_remote(host, f"docker stop {bios_sql_container.name} || true")
    run_remote(host, f"docker rm {bios_sql_container.name} || true")

    sql_resources_dir = f"{get_resources_path(config, 'sql_resources_dir')}-{tenant_name}"
    sql_log_dir = f"{get_log_path(config, 'sql_log_dir')}-{tenant_name}"
    run_sudo_remote(host, f"rm -rf {sql_resources_dir}")
    run_sudo_remote(host, f"rm -rf {sql_log_dir}")
    run_sudo_remote(host, f"mkdir -p {sql_resources_dir}")
    run_sudo_remote(host, f"mkdir -p {sql_log_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {sql_resources_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {sql_log_dir}")
    add_logs_alias(host, f"logs-sql-{tenant_name}", f"{sql_log_dir}/trino/trino.log")
    add_logs_alias(host, f"logs-sql-http-{tenant_name}", f"{sql_log_dir}/trino/trino-http.log")


def configure_sql(config, tenant):
    if not config["roles"]["compute"]:
        Log.warn("No host assigned for running compute; skipping configuring sql.")
        return

    tenant_name, user, password = get_tenant_user(tenant, "bios-sql")

    # If the SQL endpoint DNS name is not registered correctly, it is an error but not fatal.
    # hostname cannot contain underscore. Replace _ with empty string in tenant_name
    sql_dns_name = f"{tenant_name.replace('_', '')}-sql.{config['cluster_dns_name']}"
    try:
        (_, _, dns_ips) = socket.gethostbyname_ex(sql_dns_name)
        if set(config["public_ips"]) != set(dns_ips):
            Log.error(
                f"{sql_dns_name} should be set to point to the same IP addresses as"
                f" {config['cluster_dns_name']} for SQL access to work on tenant {tenant_name}."
                f" Got: {dns_ips} instead of {config['public_ips']}"
            )
    except Exception as err:
        Log.error(
            f"{sql_dns_name} should be set to point to the same IP addresses as"
            f" {config['cluster_dns_name']}:{config['public_ips']} for SQL access to work on the"
            f" {tenant_name} tenant. Got: {str(err)}"
        )

    # Generate the server.cert.pem that will be used by discovery.uri
    run_local(f"cat {CERT_FILE} {KEY_FILE} > {SERVER_CERT_FILE}")

    sql_port, newly_assigned = allocate_port(tenant_name, "bios-sql")
    del newly_assigned

    # If there is only 1 compute node, it will act as both coordinator and
    # worker. Otherwise, the first compute node would become coordinator
    is_coordinator_also_worker = False
    if len(config["roles"]["compute"]) == 1:
        is_coordinator_also_worker = True

    node_env = re.sub("-|_", "", config["cluster_dns_name"].split(".")[0]).lower()
    shared_secret = "".join(
        [random.choice(string.ascii_letters + string.digits) for _ in range(32)]
    )
    coordinator_host = config["roles"]["compute"][0]
    sql_resources_dir = get_resources_path(config, "sql_resources_dir")
    sql_log_dir = get_log_path(config, "sql_log_dir")
    worker_count = 0
    for host in config["roles"]["compute"]:
        bios_sql_container = get_docker_instance(
            config, host, CONTAINER_T_SQL, tenant_name, image_available=True
        )
        cleanup_old_container_if_present(host, tenant_name, bios_sql_container, config)
        Log.info(f"Configuring tenant {tenant_name} sql on host: {get_name_and_ip(host)}")
        cmd = (
            f"docker create --name {bios_sql_container.name} "
            f" --restart unless-stopped "
            f" --network host "
            f" -e APPLICATIONS=trino "
            f" -e BIOS_ENDPOINT=https://{config['cluster_dns_name']}:{config['lb_https_port']} "
            f" -e BIOS_TENANT={tenant_name} "
            f" -e BIOS_USER='{user}' "
            f" -e BIOS_PASSWORD='{password}' "
            f" -e SSL_CERT_FILE=/opt/bios/cacerts.pem "
            f" -v {sql_resources_dir}-{tenant_name}:/opt/bios/configuration "
            f" -v {sql_log_dir}-{tenant_name}:/var/log/apps "
            f" {bios_sql_container.image_url}"
        )
        run_remote_journal(host, cmd, bios_sql_container.name)
        put_file(host, f"{LOCAL_RES_PATH_BASE}/cacerts.pem", "/tmp/")
        run_remote(host, f"docker cp /tmp/cacerts.pem {bios_sql_container.name}:/opt/bios")
        put_file(host, f"{SERVER_CERT_FILE}", "/tmp/")
        run_remote(host, f"docker cp /tmp/server.cert.pem " f"{bios_sql_container.name}:/opt/bios")
        run_remote(host, f"rm -f /tmp/*.pem")
        run_remote(host, f"docker start {bios_sql_container.name}")
        # wait for the  docker to come up and create config directories
        time.sleep(30)

        is_coordinator = False
        if host["ip"] == coordinator_host["ip"]:
            node_id = f"{tenant_name.replace('_', '')}-coordinator"
            is_coordinator = True
        else:
            worker_count += 1
            node_id = f"{tenant_name.replace('_', '')}-worker-{worker_count}"

        # Update node.properties
        node_props_file = f"{LOCAL_RES_PATH_BASE}/{host['name']}-node.properties"
        run_local(f"cat {BIOS_CONFIGS_PATH}/node.properties > {node_props_file}")
        replace_line(NODE_ID, node_id, node_props_file)
        replace_line(NODE_ENVIRONMENT, node_env, node_props_file)
        put_file(host, node_props_file, "/tmp/node.properties")
        run_remote(
            host,
            f"docker cp /tmp/node.properties "
            f"{bios_sql_container.name}:/opt/bios/configuration/trino/",
        )
        run_remote(host, f"rm -f /tmp/node.properties")

        # Update config.properties
        config_props_file = f"{LOCAL_RES_PATH_BASE}/{host['name']}-config.properties"
        run_local(f"cat {BIOS_CONFIGS_PATH}/config.properties > {config_props_file}")
        replace_line(
            IS_COORDINATOR_ALSO_WORKER,
            "true" if is_coordinator_also_worker else "false",
            config_props_file,
        )
        replace_line(IS_COORDINATOR, "true" if is_coordinator else "false", config_props_file)
        replace_line(HTTP_PORT, int(sql_port) + 10000, config_props_file)
        replace_line(HTTPS_PORT, sql_port, config_props_file)
        replace_line(
            DISCOVERY_URI,
            f"https://{coordinator_host['ip']}:{sql_port}",
            config_props_file,
        )
        if is_coordinator:
            replace_line(WEB_UI_ENABLED, "web-ui.enabled=false", config_props_file)
        else:
            replace_line(WEB_UI_ENABLED, "", config_props_file)
        replace_line(SHARED_SECRET, shared_secret, config_props_file)

        put_file(host, config_props_file, "/tmp/config.properties")
        run_remote(
            host,
            f"docker cp /tmp/config.properties "
            f"{bios_sql_container.name}:/opt/bios/configuration/trino/",
        )
        run_remote(host, f"rm -f /tmp/config.properties")
        run_remote(host, f"docker restart {bios_sql_container.name}")

    # Configure nginx to send SQL traffic to the primary host for Trino.
    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/lb-sql.conf"
        f" {LOCAL_RES_PATH_BASE}/lb-sql-{tenant_name}.conf"
    )
    new_filename = f"lb-sql-{tenant_name}.conf"
    file = f"{LOCAL_RES_PATH_BASE}/{new_filename}"
    replace_line("TRINO_CLUSTER_DNS_NAME", sql_dns_name, file)
    replace_line("SQL_PRIMARY_HOST_PORT", f"{coordinator_host['ip']}:{sql_port}", file)
    replace_line("TENANT_NAME", tenant_name, file)
    run_local(
        f"echo 'include /var/ext_resources/conf.d/{new_filename};' >>"
        f" {LOCAL_RES_PATH_BASE}/load-balancer.conf"
    )

    bioslb_nodes = config["roles"]["lb"]
    execute_on_hosts(
        partial(update_lbs_for_sql, file),
        f"Update load balancers for tenant {tenant_name} sql",
        bioslb_nodes,
        config,
        parallel=False,
    )

    install_trino_client()

    Log.debug(f"Completed configuring sql for tenant {tenant_name}")


def configure_apps(config, tenant):
    if "compute" not in config["roles"]:
        Log.error("No host assigned for running compute; skipping configuring bios apps.")
        return

    tenant_name, user, password = get_tenant_user(tenant, "bios-integrations")

    compute_nodes = config["roles"]["compute"]
    num_instances = len(tenant["bios-integrations"]["apps_placement"])
    if num_instances > len(compute_nodes):
        Log.error(
            f"tenant {tenant_name} specified apps_placement for {num_instances} nodes,"
            f" but only {len(compute_nodes)} compute nodes are present in this cluster."
        )
        Log.error("Skipping installation of bios-integrations.")
        return

    apps_control_port_in_vm, is_new_c = allocate_port(tenant_name, "bios-integrations-control")
    apps_webhook_port_in_vm, is_new_w = allocate_port(tenant_name, "bios-integrations-webhook")
    host_list = []
    upstream_keyword = f"upstream webhook_{tenant_name}"
    upstream_text = f"{upstream_keyword} {{\n"
    apps_list = tenant["bios-integrations"]["apps_placement"]
    for host in compute_nodes:
        Log.info(
            f"Configuring tenant {tenant_name} apps ({apps_list})"
            f" on host: {get_name_and_ip(host)}"
        )

        upstream_text += f"    server {host['ip']}:{apps_webhook_port_in_vm};\n"
        host_list.append(host["ip"])

        bios_apps_container = get_docker_instance(
            config, host, CONTAINER_T_INTEGRATIONS, tenant_name, image_available=True
        )

        Log.debug(
            f"Removing any old instance of the container if present and starting a container for"
            f" {bios_apps_container.name}"
        )
        run_remote(host, f"docker stop {bios_apps_container.name} || true")
        run_remote(host, f"docker rm {bios_apps_container.name} || true")

        apps_resources_dir = (
            f"{get_resources_path(config, 'integrations_resources_dir')}-{tenant_name}"
        )
        apps_log_dir = f"{get_log_path(config, 'integrations_log_dir')}-{tenant_name}"
        run_sudo_remote(host, f"rm -rf {apps_resources_dir}")
        run_sudo_remote(host, f"rm -rf {apps_log_dir}")
        run_sudo_remote(host, f"mkdir -p {apps_resources_dir}")
        run_sudo_remote(host, f"mkdir -p {apps_log_dir}")
        run_sudo_remote(host, f"chown -R $USER:$USER {apps_resources_dir}")
        run_sudo_remote(host, f"chown -R $USER:$USER {apps_log_dir}")
        apps = ",".join(apps_list)
        for app in apps_list:
            app_name = app[len("integrations-") :]  # Remove the prefix
            add_logs_alias(
                host, f"logs-{app_name}-{tenant_name}", f"apps-{tenant_name}/{app}/{app_name}.log"
            )

        cmd = (
            f"docker create --name {bios_apps_container.name} "
            f" --restart unless-stopped "
            f" --sysctl net.core.somaxconn=4096 "
            f" -p {apps_control_port_in_vm}:9001 "
            f" -p {apps_webhook_port_in_vm}:8081  "
            f" -e BIOS_ENDPOINT=https://{config['cluster_dns_name']}:{config['lb_https_port']} "
            f" -e BIOS_TENANT={tenant_name} "
            f" -e BIOS_USER='{user}' "
            f" -e BIOS_PASSWORD='{password}' "
            f" -e SSL_CERT_FILE=/opt/bios/configuration/cacerts.pem "
            f" -e APPLICATIONS={apps} "
            f" -v {apps_resources_dir}:/opt/bios/configuration "
            f" -v {apps_log_dir}:/var/log/apps "
            f" {bios_apps_container.image_url}"
        )
        run_remote_journal(host, cmd, bios_apps_container.name)
        put_file(host, f"{LOCAL_RES_PATH_BASE}/cacerts.pem", f"{apps_resources_dir}")
        run_remote(
            host,
            f"docker cp {bios_apps_container.name}:/etc/supervisor/supervisord.conf"
            f" {apps_resources_dir}",
        )
        additional_supervisord_conf = f"""

[inet_http_server]
port = 0.0.0.0:9001
username = {config['xmlrpc_user']}
password = {config['xmlrpc_password']}
"""
        run_remote(
            host,
            f'echo "{additional_supervisord_conf}" >> {apps_resources_dir}/supervisord.conf',
        )
        run_remote(
            host,
            f"docker cp {apps_resources_dir}/supervisord.conf"
            f" {bios_apps_container.name}:/etc/supervisor/",
        )
        run_remote(host, f"docker start {bios_apps_container.name}")
    upstream_text += "}"

    # Register with bios server: hosts/ports for the deployed bios-integrations instances.
    if is_new_c or is_new_w:
        Log.debug(
            f"Registering bios-integrations with bios server: {tenant_name}, {host_list},"
            f" {apps_control_port_in_vm}, {apps_webhook_port_in_vm} ..."
        )
        session = create_bios_session_system(config)
        try:
            response = session.deregister_apps_service(tenant_name)
            Log.debug(f"De-registration done: {response}")
        except Exception as err:
            Log.debug(
                f"Most likely bios-integrations have not been registered earlier."
                f" Unable to deregister apps_service for {tenant_name} tenant. Got {str(err)}"
            )
        response = session.register_apps_service(
            tenant_name, host_list, apps_control_port_in_vm, apps_webhook_port_in_vm
        )
        Log.debug(f"Registration done: {response}")

    # Configure nginx to create a webhook endpoint
    file = f"{LOCAL_RES_PATH_BASE}/load-balancer.conf"

    result = run_local(f"grep '{upstream_keyword}' {file}", accepted_exit_codes=[1])
    if not result.failed:
        Log.warn("Webhook endpoint is configured already in load balancers, skipping installation")
        return

    replace_line(
        f"# {BIOS_APPS_UPSTREAMS_ANCHOR}",
        f"{upstream_text}\n\n# {BIOS_APPS_UPSTREAMS_ANCHOR}",
        file,
    )
    webhook_lb_path = "/integration"
    if "bios-integrations" in tenant and "webhook_lb_path" in tenant["bios-integrations"]:
        webhook_lb_path = tenant["bios-integrations"]["webhook_lb_path"]
    location_text = f"""    location {webhook_lb_path}/{tenant_name} {{
        access_log /var/log/nginx/webhook-{tenant_name}.log upstream_info;
        add_header 'Access-Control-Allow-Origin' '*';
        add_header 'Access-Control-Allow-Credentials' 'true';
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
        add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
        proxy_pass http://webhook_{tenant_name}/;
    }}"""
    replace_line(
        f"# {BIOS_APPS_LOCATIONS_ANCHOR}",
        f"{location_text}\n\n# {BIOS_APPS_LOCATIONS_ANCHOR}",
        file,
    )

    nginx_nodes = config["roles"]["lb"]
    execute_on_hosts(
        partial(update_lbs_for_bios_apps, tenant_name),
        f"Update load balancers for tenant {tenant_name} bios apps",
        nginx_nodes,
        config,
    )
    Log.debug(f"Completed configuring bios apps for tenant {tenant_name}")


def configure_load(config, tenant):
    if "load" not in config["roles"]:
        Log.error("No host assigned for running load; skipping configuring load generator.")
        return

    tenant_name = tenant["tenant_name"]
    Log.info(f"Configuring load generator for tenant {tenant_name}")

    configure_bios_for_load(config, tenant)

    host = config["roles"]["load"][0]
    bios_apps_container = get_docker_instance(
        config, host, CONTAINER_T_LOAD, tenant_name, image_available=True
    )
    container = bios_apps_container.name

    load_resources_dir = f"{get_resources_path(config, 'load_resources_dir')}-{tenant_name}"
    load_log_dir = f"{get_log_path(config, 'load_log_dir')}-{tenant_name}"
    run_sudo_remote(host, f"rm -rf {load_resources_dir}")
    run_sudo_remote(host, f"rm -rf {load_log_dir}")
    run_sudo_remote(host, f"mkdir -p {load_resources_dir}")
    run_sudo_remote(host, f"mkdir -p {load_log_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {load_resources_dir}")
    run_sudo_remote(host, f"chown -R $USER:$USER {load_log_dir}")
    add_logs_alias(
        host,
        f"logs-load-{tenant_name}",
        f"{load_log_dir}/load-generator/load-generator.log",
    )
    to_bash_profile(
        host,
        f"alias load-edit-{tenant_name}="
        f'"vi {load_resources_dir}/load-generator/load.properties"',
    )
    to_bash_profile(
        host,
        f'alias load-start-{tenant_name}="docker restart {container} && '
        f'docker exec load-{tenant_name} /opt/bios/apps/load-generator/start-load-generator.sh"',
    )

    cmd = (
        f"docker run --name {container} -d "
        f" --restart unless-stopped "
        f" -v {load_resources_dir}:/opt/bios/configuration "
        f" -v {load_log_dir}:/var/log/apps "
        f" {bios_apps_container.image_url}"
    )

    Log.debug(
        f"Removing any old instance of the container if present and starting"
        f" a container for {container}"
    )
    run_remote(host, f"docker stop {container} || true")
    run_remote(host, f"docker rm {container} || true")
    run_remote_journal(host, cmd, container)

    # Set up the load generator.
    load_profile_type = "test"
    if tenant["load"]["profile_type"]:
        load_profile_type = tenant["load"]["profile_type"].lower()
    if load_profile_type not in ["test", "perf"]:
        load_profile_type = "test"
    Log.debug(f"profile_type: {load_profile_type}")

    # TODO(pradeep) Add "patientVisits.json" after noise is removed
    # for log and exception "Missed to lookup context with a foreign key".
    json_files = [
        "auxiliary.json",
        "boutique_viewed_signal.json",
        "countryContext.json",
        "covidDataSignal.json",
        "customer_registered_signal.json",
        "device_context.json",
        "doctor.json",
        "enrichedContext.json",
        "homepage_scroll_signal.json",
        "homepage_view_signal.json",
        "machine.json",
        "order_placed_signal.json",
        "plp_scrolled_signal.json",
        "product_added_to_cart_signal.json",
        "product_impression_signal.json",
        "product_listing_viewed_signal.json",
        "product_ordered_signal.json",
        "product_searched_signal.json",
        "product_view_signal.json",
        "resourceType.json",
        "staff.json",
        "session_started_signal.json",
        "special_page_viewed_signal.json",
        "venue.json",
        "visitor_context.json",
        "warehouse_context.json",
        "warehouse_inventory_context.json",
        "workspace.json",
        "warehouse_picker_task_signal.json",
    ]

    src = "/opt/bios/apps/load-generator/load-profiles"
    cmd_beginning = f"docker exec {container} cp -r {src}"
    dest = "/opt/bios/configuration/load-generator/load-profiles"
    run_remote(host, f"docker exec {container} mkdir -p {dest}")
    # Temporary workaround until we fix productCatalog to work well over a long period of time.
    run_remote(host, f"docker exec {container} rm -f {src}/product_catalog.json")
    run_remote(host, f"docker exec {container} rm -f {dest}/product_catalog.json")
    for file in json_files:
        if load_profile_type == "perf":
            run_remote(host, f"docker cp {container}:{src}/{file} /tmp/")
            run_local(f"scp -o StrictHostKeyChecking=no ubuntu@{host['ip']}:/tmp/{file} /tmp/")
            json_file = f"/tmp/{file}"
            Log.debug(f"Adjusting peakRequestSize for: {file}")
            with open(json_file, "r", encoding="utf-8") as infile:
                stream_cfg = json.load(infile)
                stream_cfg["peakRequestSize"] = int(int(stream_cfg["peakRequestSize"]) * 10)
                with open(json_file, "w", encoding="utf-8") as outfile:
                    json.dump(stream_cfg, outfile, indent=4)
            run_local(f"scp -o StrictHostKeyChecking=no {json_file} ubuntu@{host['ip']}:/tmp/ ")
            run_remote(host, f"docker cp {json_file} {container}:{src}/")
        Log.debug(f"Copying file: {file} to {dest}/")
        run_remote(host, f"{cmd_beginning}/{file} {dest}/")

    run_remote(host, f"{cmd_beginning}/../log4j.xml {dest}/../")
    run_sudo_remote(host, f"chown -R $USER:$USER {load_resources_dir}")
    run_local(f"mkdir -p {LOCAL_RES_PATH_BASE}")

    # Update and copy /isima/<container>/load-generator/load.properties
    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/load.properties {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/load.properties"
    storage_host = config["roles"]["storage"][0]["ip"]
    storage_port = str(config["https_port"])
    user = tenant["load"]["user"]
    password = tenant["load"]["password"]
    effective_load_config = copy.deepcopy(config["load"])
    deep_merge_dictionaries(effective_load_config, tenant["load"])
    replace_line("CLUSTER_HOST", storage_host, file)
    replace_line("BIOS_PORT", storage_port, file)
    replace_line("BIOS_USER", user, file)
    replace_line("BIOS_PASSWORD", password, file)
    replace_line("LOAD_PATTERN", effective_load_config["load_pattern"], file)
    replace_line("INSERT_THREADS", effective_load_config["insert_threads"], file)
    replace_line("SELECT_THREADS", effective_load_config["select_threads"], file)
    replace_line("UPSERT_THREADS", effective_load_config["upsert_threads"], file)
    replace_line("PER_CALL_SLEEP_MS", effective_load_config["per_call_sleep_ms"], file)
    put_file(host, file, f"{load_resources_dir}/load-generator/")
    put_file(
        host, f"{BIOS_CONFIGS_PATH}/load_schema.json", f"{load_resources_dir}/load-generator/"
    )

    put_file(host, f"{LOCAL_RES_PATH_BASE}/cacerts.pem", load_resources_dir)

    run_remote(
        host,
        f"docker exec {container} tar -xzf /var/lib/apps/load-generator/apache-jmeter-5.1.1.tgz"
        f" --directory=/var/lib/apps/load-generator",
    )
    try:
        run_remote(
            host,
            f"docker exec {container} /opt/bios/utils/provision_streams.py  --skip"
            f" https://{config['cluster_dns_name']}:{config['lb_https_port']} {user} {password}"
            f" /opt/bios/configuration/load-generator/load_schema.json",
        )
    except RuntimeError as error:
        Log.error(f"Error in provisioning test streams: {error}")
        # try again
        run_remote(
            host,
            f"docker exec {container} /opt/bios/utils/provision_streams.py  --skip"
            f" https://{config['cluster_dns_name']}:{config['lb_https_port']} {user} {password}"
            f" /opt/bios/configuration/load-generator/load_schema.json",
        )

    # Set up load generator to run under supervisord
    loadgen_supervisor_conf = f"{BIOS_CONFIGS_PATH}/load-generator.conf"
    put_file(host, loadgen_supervisor_conf, f"{load_resources_dir}/load-generator/")
    dest_dir = "/etc/supervisor/conf.d/"
    run_remote(
        host,
        f"docker exec {container} cp /opt/bios/configuration"
        f"/load-generator/load-generator.conf {dest_dir}",
    )

    # Start running the load.
    run_remote(host, f"docker restart {container}")
    Log.debug(f"Completed configuring load generator for tenant {tenant_name}")


def configure_bios_for_load(config: dict, tenant: dict):
    """Set up necessary bios shared properties and restart the servers"""
    tenant_name = tenant["tenant_name"]
    Log.debug(f"Updating bios shared properties to run load test for tenant {tenant_name}")

    with bios.login(
        f"https://{config['cluster_dns_name']}:{config['lb_https_port']}",
        "systemadmin@isima.io",
        config["systemadmin_password"],
    ) as session:
        for name, value in config["load"]["shared_properties"].items():
            session.set_property(name, str(value))
        new_fast_track_signals = [
            f"{tenant_name}.{signal}" for signal in config["load"]["fast_track_signals"]
        ]
        prop_name = "prop.maintenance.fastTrackSignals"
        current_fast_track_signals = session.get_property(prop_name).strip()
        if current_fast_track_signals:
            fast_track_signals = set(current_fast_track_signals.split(","))
        else:
            fast_track_signals = set()
        fast_track_signals.update(new_fast_track_signals)
        session.set_property(prop_name, ",".join(fast_track_signals))

    for host in config["roles"]["storage"]:
        Log.debug(f"Restarting bi(OS) node {host['name']}")
        bios_container = get_docker_instance(config, host, CONTAINER_T_BIOS)
        run_remote(host, f"docker restart {bios_container.name}")
        wait_for_bios_up(None, f"https://{host['ip']}:{config['https_port']}")


def update_lbs_for_sql(lb_sql_conf_filename, index, host, config):
    del index
    remote_res_path = get_resources_path(config, "lb_resources_dir")
    # Copy config file into remote resources directory and use it.
    put_file(host, lb_sql_conf_filename, f"{remote_res_path}/conf.d/")
    put_file(host, f"{LOCAL_RES_PATH_BASE}/load-balancer.conf", f"{remote_res_path}/conf.d/")

    # Restart the container and wait for load balancer to be up.
    container_name = config["container_name"][CONTAINER_T_LB]
    run_remote(host, f"docker exec {container_name} nginx -t")
    run_remote(host, f"docker exec {container_name} nginx -s reload")
    wait_for_bios_up(host, f"https://localhost:{config['lb_https_port']}")


def pull_lb_configuration(config: dict):
    """Pulls LB configuration to the local resource directory and validates the config file
    If there are differences in remote configs among LB nodes, the method rises RuntimeError.
    """
    Log.info("Pulling configuration files from LB nodes")
    lb_nodes = config["roles"]["lb"]

    # Fetch LB configuration files and check if there are any differences
    remote_resources_path = get_resources_path(config, "lb_resources_dir")
    remote_conf_file = f"{remote_resources_path}/conf.d/load-balancer.conf"
    first_conf_file = None
    for i, node in enumerate(lb_nodes):
        node_name = node["name"]
        temp_conf_file = f"/tmp/load-balancer-{node_name}.conf"
        get_file(node, remote_conf_file, temp_conf_file)
        if i == 0:
            first_conf_file = temp_conf_file
        else:
            diff_result = run_local(
                f"diff -uw {first_conf_file} {temp_conf_file}", accepted_exit_codes={1}
            )
            if diff_result.stdout:
                raise RuntimeError(
                    f"There are differences in {remote_conf_file} file"
                    f" between nodes {lb_nodes[0]['name']} and {node_name}:\n{diff_result.stdout}"
                )

    # Verify whether necessary anchors are embedded in the config file
    for anchor in [BIOS_APPS_UPSTREAMS_ANCHOR, BIOS_APPS_LOCATIONS_ANCHOR]:
        result = run_local(f"grep '# {anchor}' {first_conf_file}", accepted_exit_codes={1})
        if result.failed:
            raise RuntimeError(
                f"Files {remote_conf_file} in LB nodes are missing necessary anchor '# {anchor}'"
            )

    # The config file is valid, copy it to the resource directory
    local_conf_file = f"{LOCAL_RES_PATH_BASE}/load-balancer.conf"
    run_local(f"cp {first_conf_file} {local_conf_file}")
    Log.info(f"Done pulling LB configuration file to {local_conf_file}")


def update_lbs_for_bios_apps(tenant_name, index, host, config):
    del index
    add_logs_alias(host, f"logs-bioslb-webhook-{tenant_name}", f"bioslb/webhook-{tenant_name}.log")
    remote_res_path = get_resources_path(config, "lb_resources_dir")
    # Copy config file into remote resources directory and use it.
    put_file(host, f"{LOCAL_RES_PATH_BASE}/load-balancer.conf", f"{remote_res_path}/conf.d/")

    # Restart the container and wait for load balancer to be up.
    container_name = config["container_name"][CONTAINER_T_LB]
    run_remote(host, f"docker exec {container_name} nginx -t")
    run_remote(host, f"docker exec {container_name} nginx -s reload")
    wait_for_bios_up(host, f"https://localhost:{config['lb_https_port']}")
