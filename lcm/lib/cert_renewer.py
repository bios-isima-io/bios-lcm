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

import sys
import time
from typing import Any, Dict

from lib.common import (
    get_container_resources_directory,
    run_local,
    run_remote,
    run_sudo_local,
)
from lib.constants import CONTAINER_T_STORAGE
from lib.log import Log


def backup_dbdozer_trust_stores(host: Dict[str, str], current_day_str: str):
    dbdozer_dir = get_container_resources_directory(host, "dbdozer", "/var/lib/bios-maintainer")
    Log.info(
        f"  Backing up {dbdozer_dir}/db.truststore to {dbdozer_dir}/db.truststore {current_day_str}"
    )
    run_local(f"cp {dbdozer_dir}/db.truststore {dbdozer_dir}/db.truststore.{current_day_str}")
    Log.info("  Done")


def backup_storage_node_trust_stores(
    host: Dict[str, str], current_day_str: str, legacy_store: bool
):
    server_dir = get_container_resources_directory(host, "bios", "/opt/bios/configuration")
    db_dir = get_container_resources_directory(host, CONTAINER_T_STORAGE, "/var/ext_resources")
    server_store = "server.p12"
    if legacy_store:
        server_store = "server.new.p12"
    Log.info(
        f"  Backing up {server_dir}/{server_store} and {db_dir}/db.truststore on host: {host['ip']}"
    )
    run_remote(
        host, f"cp {server_dir}/{server_store} {server_dir}/{server_store}.{current_day_str}"
    )
    run_remote(host, f"cp {server_dir}/db.truststore {server_dir}/db.truststore.{current_day_str}")
    if legacy_store:
        run_remote(host, f"cp {db_dir}/{server_store} {db_dir}/{server_store}.{current_day_str}")
    run_remote(host, f"cp {db_dir}/db.truststore {db_dir}/db.truststore.{current_day_str}")
    Log.info("  Done")


def backup_sql_container_certs(host: Dict[str, str], current_day_str: str):
    sql_containers = []
    result = run_remote(host, "docker ps -a | grep bios-sql | awk '{ print $10 }'")
    for line in result.stdout.split("\n"):
        sql_containers.append(line.strip())
    for container in sql_containers:
        if container:
            Log.info(f"Updating container: {container} on host: {host['ip']}")
            run_remote(
                host,
                f"docker cp {container}:/opt/bios/server.cert.pem "
                f"/tmp/server.cert.pem.{current_day_str}",
            )
            run_remote(
                host, f"docker cp /tmp/server.cert.pem.{current_day_str} {container}:/opt/bios/"
            )
    Log.info("  Done")


def backup_lb_certs(host: Dict[str, str], today_str: str):
    Log.info(f"Backing up web.cert.pem and web.key.pem on host: {host['ip']}")
    lb_dir = get_container_resources_directory(host, "bioslb", "/var/ext_resources")
    run_remote(host, f"mkdir -p {lb_dir}/old-certs-{today_str}")
    run_remote(
        host, f"cp {lb_dir}/web.cert.pem {lb_dir}/web.key.pem {lb_dir}/old-certs-{today_str}/"
    )
    Log.info("  Done")


def backup_certs_and_stores(config: Dict[str, Any], current_day_str: str, legacy_store: bool):
    # compute nodes backup
    compute_nodes = config["roles"]["compute"]
    # Log.info(f"compute nodes: {compute_nodes}, hosts: {config['hosts']}")
    for host in compute_nodes:
        Log.info(f"  Backing up files on compute node host: {host['ip']}")
        backup_sql_container_certs(host, current_day_str)
    # dbdozer backup
    lcm_nodes = config["roles"]["lcm"]
    for host in lcm_nodes:
        Log.info(f"  Backing up files on lcm: {host['ip']}")
        backup_dbdozer_trust_stores(host, current_day_str)
    # storage nodes backup
    storage_nodes = config["roles"]["storage"]
    for host in storage_nodes:
        Log.info(f"  Backing up files on storage node host: {host['ip']}")
        backup_storage_node_trust_stores(host, current_day_str, legacy_store)
    # lb nodes backup
    lb_nodes = config["roles"]["lb"]
    for host in lb_nodes:
        Log.info(f"  Backing up files on lb host: {host['ip']}")
        backup_lb_certs(host, current_day_str)


def copy_trust_store_to_dbdozer(host: Dict[str, str], renewal_dir: str):
    dbdozer_dir = get_container_resources_directory(host, "dbdozer", "/var/lib/bios-maintainer")
    Log.info(f"Copying db.truststore to {dbdozer_dir}/")
    run_local(f"cp {renewal_dir}/db.truststore {dbdozer_dir}/")


def copy_trust_stores_to_storage_node(host: Dict[str, str], renewal_dir: str, legacy_store: bool):
    server_dir = get_container_resources_directory(host, "bios", "/opt/bios/configuration")
    db_dir = get_container_resources_directory(host, CONTAINER_T_STORAGE, "/var/ext_resources")
    server_store = "server.p12"
    if legacy_store:
        server_store = "server.new.p12"
    Log.info(
        f"  Copying {renewal_dir}/{server_store} and {renewal_dir}/db.truststore "
        f"to host: {host['name']}"
    )
    run_local(f"scp {renewal_dir}/{server_store} {host['name']}:{server_dir}/")
    run_local(f"scp {renewal_dir}/db.truststore {host['name']}:{server_dir}/")
    if legacy_store:
        run_local(f"scp {renewal_dir}/{server_store} {host['name']}:{db_dir}/")
    run_local(f"scp {renewal_dir}/db.truststore {host['name']}:{db_dir}/")


def copy_certs_to_sql_container(host: Dict[str, str], renewal_dir: str):
    run_local(f"scp {renewal_dir}/web.full.pem {host['name']}:/tmp/server.cert.pem")
    sql_containers = []
    result = run_remote(host, "docker ps -a | grep bios-sql | awk '{ print $10 }'")
    for line in result.stdout.split("\n"):
        sql_containers.append(line.strip())
    for container in sql_containers:
        if container:
            run_remote(host, f"docker cp /tmp/server.cert.pem {container}:/opt/bios/")


def copy_certs_to_lb(host: Dict[str, str], renewal_dir: str):
    lb_dir = get_container_resources_directory(host, "bioslb", "/var/ext_resources")
    run_local(f"scp {renewal_dir}/web.cert.pem {host['name']}:{lb_dir}/")
    run_local(f"scp {renewal_dir}/web.key.pem {host['name']}:{lb_dir}/")


def copy_new_certs_and_stores_to_targets(
    config: Dict[str, Any], renewal_dir: str, legacy_store: bool
):
    # copy to compute nodes
    compute_nodes = config["roles"]["compute"]
    for host in compute_nodes:
        copy_certs_to_sql_container(host, renewal_dir)
    # copy to dbdozer
    lcm_nodes = config["roles"]["lcm"]
    for host in lcm_nodes:
        copy_trust_store_to_dbdozer(host, renewal_dir)
    # copy to storage nodes
    storage_nodes = config["roles"]["storage"]
    for host in storage_nodes:
        copy_trust_stores_to_storage_node(host, renewal_dir, legacy_store)
    # copy to lb nodes
    lb_nodes = config["roles"]["lb"]
    for host in lb_nodes:
        copy_certs_to_lb(host, renewal_dir)


def fetch_certs_and_stores(
    config: Dict[str, Any], cluster_dns_name: str, renewal_dir: str, legacy_store: bool
):
    # copy the certbot renewed certs to the renewal directory
    Log.info(f"  Copying web.cert.pem & web.key.pem to: {renewal_dir}/")
    run_sudo_local(
        f"sudo cp /etc/letsencrypt/live/{cluster_dns_name}/fullchain.pem "
        f"{renewal_dir}/web.cert.pem"
    )
    run_sudo_local(f"sudo chown ubuntu:ubuntu {renewal_dir}/web.cert.pem")
    run_local(f"chmod 666 {renewal_dir}/web.cert.pem")
    run_sudo_local(
        f"sudo cp /etc/letsencrypt/live/{cluster_dns_name}/privkey.pem {renewal_dir}/web.key.pem"
    )
    run_sudo_local(f"sudo chown ubuntu:ubuntu {renewal_dir}/web.key.pem")
    run_local(f"chmod 666 {renewal_dir}/web.key.pem")

    if legacy_store:
        # append root cert isrg_x1_root_ca.pem web.cert.pem
        run_local(
            f"cat /home/ubuntu/cert_renewals/isrg_x1_root_ca.pem >> " f"{renewal_dir}/web.cert.pem"
        )

    # generate web.full.pem containing public and private keys (used by bios-sql-* containers)
    Log.info("  Generating web.full.pem")
    run_local(
        f"cat {renewal_dir}/web.cert.pem {renewal_dir}/web.key.pem > "
        f"{renewal_dir}/web.full.pem"
    )

    # copy server.new.p12 & db.truststore from signal-1
    signal_1_host_ip = config["hosts"]["signal-1"]
    bios_config_dir = get_container_resources_directory(
        signal_1_host_ip, "bios", "/opt/bios/configuration"
    )
    server_store = "server.p12"
    if legacy_store:
        # for bios.isima.io we need to support older server.p12 (self-signed certs for PE)
        # as well as new store server.new.p12 (for all internal communication)
        server_store = "server.new.p12"
    Log.info(f"  Copying signal-1:{bios_config_dir}/{server_store} to: {renewal_dir}/")
    run_local(f"scp signal-1:{bios_config_dir}/{server_store} {renewal_dir}/")
    container_name = config["container_name"][CONTAINER_T_STORAGE]
    bios_storage_config_dir = get_container_resources_directory(
        signal_1_host_ip, container_name, "/var/ext_resources"
    )
    Log.info(f"  signal-1:{bios_storage_config_dir}/db.truststore to: {renewal_dir}/")
    run_local(f"scp signal-1:{bios_storage_config_dir}/db.truststore {renewal_dir}/")

    # list all files in the renewal directory
    result = run_local(f"ls -la {renewal_dir}/")
    for line in result.stdout.split("\n"):
        Log.info(f"  {line}")
    Log.info("  Done")


def update_trust_stores(renewal_dir: str, current_day_str: str, legacy_store: bool):
    # create server.new_certs.p12 store with the latest cert files
    Log.info(f"  Creating new store {renewal_dir}/server.new_certs.p12 with latest certs ...")
    run_local(
        f"openssl pkcs12 -export -in {renewal_dir}/web.cert.pem -inkey "
        f"{renewal_dir}/web.key.pem -out {renewal_dir}/server.new_certs.p12 -name "
        f"bios_{current_day_str} -password pass:secret"
    )
    Log.info("  Done")

    # import the new store into the old store
    server_store = "server.p12"
    if legacy_store:
        server_store = "server.new.p12"
    Log.info(f"  Importing server.new_certs.p12 to {server_store} ...")
    run_local(
        f"keytool -importkeystore -deststorepass secret -destkeystore "
        f"{renewal_dir}/{server_store} -srckeystore {renewal_dir}/server.new_certs.p12 "
        f"-deststoretype PKCS12 -srcstoretype PKCS12 -srcstorepass secret "
        f" -alias bios_{current_day_str}"
    )
    Log.info("  Done")

    # update db.truststore with latest cert
    Log.info(f"  Updating {renewal_dir}/db.truststore with new cert")
    run_local(
        f"keytool -import -file {renewal_dir}/web.full.pem -alias bios_{current_day_str} "
        f"-keystore {renewal_dir}/db.truststore -storepass secret -noprompt"
    )
    Log.info("  Done")

    # verify the contents of the stores
    Log.info(f"  Verifying that {server_store} is updated with alias bios_{current_day_str}\n")
    result = run_local(
        f"keytool -list -v -keystore {renewal_dir}/{server_store} -storepass secret "
        f"-storetype PKCS12 -alias bios_{current_day_str}"
    )
    for line in result.stdout.split("\n"):
        Log.info(f"  {line}")
    result = input("\nDoes the above cert show renewed validity (yes/no) ? ")
    if result.lower() not in ["yes", "y"]:
        sys.exit(-1)
    Log.info(f"  Verifying that db.truststore is updated with alias bios_{current_day_str}\n")
    result = run_local(
        f"keytool -list -v -keystore {renewal_dir}/db.truststore -storepass secret "
        f"-storetype PKCS12 -alias bios_{current_day_str}"
    )
    for line in result.stdout.split("\n"):
        Log.info(f"  {line}")


def replace_certs_and_restart_lb_nodes(config: Dict[str, Any]):
    lb_hosts = config["roles"]["lb"]
    for host in lb_hosts:
        result = input(f"Restart bioslb on host {host['name']} - (yes/no) ? ")
        if result.lower() not in ["yes", "y"]:
            Log.info(f"  Skipping bioslb restart on host: {host['name']}")
        else:
            run_remote(host, "docker exec bioslb nginx -s reload")
            Log.info("Restarted bioslb. Sleeping for 30 seconds... ")
            time.sleep(30)
            Log.info("Done")
