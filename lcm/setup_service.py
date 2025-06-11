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

import argparse
import os
import sys
from typing import List

from create_tenant import create_tenant
from lib.common import (
    execute_wrapped,
    generate_password,
    initialize_lcm,
    replace_line,
    run_local,
)
from lib.constants import BIOS_SERVICES_PATH, DATA_DIR
from lib.log import Log


def find_available_services() -> List[str]:
    """Finds services currently available"""
    path = BIOS_SERVICES_PATH
    return [file for file in os.listdir(path) if os.path.isdir(f"{path}/{file}")]


def prepare_tenant_config(config: dict, service_name: str, tenant_name: str) -> str:
    """Create a tenant configuration file from service template.

    Args:
        config: LCM configuration object
        service_name: Service name
        tenant_name: Tenant name
    Returns: str: Pathname for the created tenant configuration file
    """
    del config
    service_config_path = f"{BIOS_SERVICES_PATH}/{service_name}"

    if not os.path.exists(service_config_path):
        raise FileNotFoundError(f"Service config path {service_config_path} not found")

    tenant_config_template = f"{service_config_path}/tenant_{service_name}.yaml"
    basename = f"tenant.{tenant_name}.{service_name}.yaml"
    file = f"{DATA_DIR}/{basename}"
    run_local(f"cp --no-preserve=mode {tenant_config_template} {file}")
    # fill variables in the template
    replace_line("${TENANT_NAME}", tenant_name, file)
    replace_line("${SERVICE_CONFIG_PATH}", service_config_path, file)
    support_user_password = generate_password(16)
    replace_line("${SUPPORT_USER_PASSWORD}", support_user_password, file)
    data_user_password = generate_password(16)
    replace_line("${DATA_USER_PASSWORD}", data_user_password, file)
    app_master_password = generate_password(16)
    replace_line("${APP_MASTER_PASSWORD}", app_master_password, file)

    return file


def main():
    services = ", ".join(find_available_services())
    parser = argparse.ArgumentParser(description="Set up a plugin service")
    parser.add_argument(
        "service_name",
        metavar="SERVICE_NAME",
        type=str,
        help=f"Service name, available services: {services}",
    )
    parser.add_argument("tenant_name", metavar="TENANT_NAME", type=str, help="Tenant name")

    args = parser.parse_args()
    service_name = args.service_name
    tenant_name = args.tenant_name

    config = initialize_lcm()

    tenant_file = prepare_tenant_config(config, service_name, tenant_name)

    create_tenant(config, tenant_file)

    message = [f"Completed setting up tenant '{tenant_name}' with service '{service_name}'.\n"]
    message.append("        Tenant configuration file for this set up is:")
    message.append(f"          {tenant_file}\n")
    message.append("        Names and passwords of internal users are available in the file.")
    Log.marker("\n".join(message))


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
