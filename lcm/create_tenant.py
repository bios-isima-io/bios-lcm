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
import os
import sys

import bios
import yaml
from bios import ErrorCode, ServiceError
from lib.bios_apps import (
    configure_apps,
    configure_load,
    configure_sql,
    pull_lb_configuration,
)
from lib.common import (
    execute_wrapped,
    initialize_lcm,
    load_yaml_file,
    replace_line,
    run_local,
)
from lib.common_with_bios import create_bios_session, create_bios_session_system
from lib.constants import LOCAL_RES_PATH_BASE
from lib.docker_instance import retabulate_version_numbers
from lib.log import Log
from lib.schema import update_tenant


def create_tenant(config: dict, tenant_file: str):
    """Create a tenant according to the tenant configuration file.

    Args:
        config (dict): LCM cluster config object
        tenant_file (str): Tenant configuration file name
    """
    # First we pull the latest LB configs because there may be local changes
    pull_lb_configuration(config)

    basename = os.path.basename(tenant_file)
    run_local(f"cp --no-preserve=mode {tenant_file} {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/{basename}"
    replace_line("${CLUSTER_DNS_NAME}", config["cluster_dns_name"], file)
    replace_line("${LB_HTTPS_PORT}", config["lb_https_port"], file)
    tenant = load_yaml_file(file)
    tenant_name = tenant["tenant_name"]
    replace_line("${TENANT_NAME}", tenant_name, file)
    replace_line("${SUPPORT_USER_PASSWORD}", tenant["support_user_password"], file)
    if "data_user_password" in tenant:
        replace_line("${DATA_USER_PASSWORD}", tenant["data_user_password"], file)
    # reload
    tenant = load_yaml_file(file)

    Log.info(f"Creating a new tenant: {tenant_name}")
    tenant_config = {}
    tenant_config["tenantName"] = tenant_name
    session = create_bios_session_system(config)
    try:
        session.create_tenant(tenant_config)
    except ServiceError as err:
        if err.error_code == ErrorCode.TENANT_ALREADY_EXISTS:
            Log.warn(f"Tenant {tenant_name} exists already")
        else:
            raise

    for entry in tenant["users"]:
        Log.info(f"Creating user {entry['user']}")
        user = bios.User(
            entry["user"],
            entry["full_name"],
            tenant_name,
            entry["password"],
            entry["roles"],
        )
        try:
            session.create_user(user)
        except ServiceError as err:
            if err.error_code == ErrorCode.RESOURCE_ALREADY_EXISTS:
                Log.warn(f"User {entry['user']} exists already, only changing password")
                session.change_password(email=user.email, new_password=user.password)
            else:
                raise

    support_user = f"support+{tenant_name}@isima.io"
    Log.info(f"Creating support user {support_user}")
    user = bios.User(
        support_user,
        f"Support user for {tenant_name}",
        tenant_name,
        tenant["support_user_password"],
        ["TenantAdmin", "Report"],
    )
    try:
        session.create_user(user)
    except ServiceError as err:
        if err.error_code == ErrorCode.RESOURCE_ALREADY_EXISTS:
            Log.warn(f"Support user {support_user} exists already, only changing password")
            session.change_password(email=user.email, new_password=user.password)
        else:
            raise

    tenant_session = create_bios_session(config, support_user, tenant["support_user_password"])

    schema_file = tenant.get("schema_file")
    if schema_file:
        with open(schema_file, "r", encoding="utf-8") as file:
            src = file.read()
        src = src.replace("${CLUSTER_DNS_NAME}", str(config["cluster_dns_name"]))
        src = src.replace("${LB_HTTPS_PORT}", str(config["lb_https_port"]))
        src = src.replace("${TENANT_NAME}", str(tenant_name))
        src = src.replace("${DATA_USER_PASSWORD}", str(tenant["data_user_password"]))
        try:
            schema = json.loads(src)
        except json.decoder.JSONDecodeError:
            schema = yaml.safe_load(src)
        orig_dir = os.getcwd()
        work_dir = os.path.dirname(schema_file)
        os.chdir(work_dir)
        Log.info(f"Configuring schema in {schema_file}")
        update_tenant(tenant_session, schema)
        os.chdir(orig_dir)

    if "bios-integrations" in tenant:
        configure_apps(config, tenant)

    if "bios-sql" in tenant:
        configure_sql(config, tenant)

    if "load" in tenant:
        configure_load(config, tenant)


def main():
    print_help = False
    if len(sys.argv) < 2:
        print_help = True
    else:
        first_arg = sys.argv[1]
        if first_arg in ["--help", "-h"]:
            print_help = True

    if print_help:
        print(
            f"""Usage: {sys.argv[0]} <tenant config yaml file> [verbose]

                verbose: optionally print verbose logs
        """
        )
    else:
        if len(sys.argv) >= 3 and sys.argv[2] == "verbose":
            Log.set_verbose_output(True)

        config = initialize_lcm()
        retabulate_version_numbers(config)

        tenant_file = sys.argv[1]

        create_tenant(config, tenant_file)
        Log.marker("Completed creating tenant")


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
