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

from lib.common import execute_wrapped, initialize_lcm, run_remote
from lib.common_with_bios import create_bios_session_system
from lib.log import Log


def delete_tenant_core(config, name):
    Log.info(f"Stopping and removing docker containers for tenant {name}")
    host = config["roles"]["load"][0]
    run_remote(host, f"docker kill $(docker ps -q -f name=load-{name}) || true")
    run_remote(host, f"docker rm $(docker ps -a -q -f name=load-{name}) || true")

    compute_nodes = config["roles"]["compute"]
    for host in compute_nodes:
        run_remote(host, f"docker kill $(docker ps -q -f name=bios-sql-{name}) || true")
        run_remote(host, f"docker rm $(docker ps -a -q -f name=bios-sql-{name}) || true")
        run_remote(host, f"docker kill $(docker ps -q -f name=bios-integrations-{name}) || true")
        run_remote(host, f"docker rm $(docker ps -a -q -f name=bios-integrations-{name}) || true")

    Log.info(f"Deleting tenant {name} from bi(OS)")
    session = create_bios_session_system(config)
    session.delete_tenant(name)


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
            f"""Usage: {sys.argv[0]} <tenant name> [verbose]

                verbose: optionally print verbose logs
        """
        )
    else:
        if len(sys.argv) >= 3 and sys.argv[2] == "verbose":
            Log.set_verbose_output(True)

        config = initialize_lcm()

        tenant_name = sys.argv[1]

        delete_tenant_core(config, tenant_name)
        Log.marker(
            f"""Partially deleted tenant {tenant_name}

            Note that currently deletion of a tenant leaves behind many configuration items.

            Do not create another tenant with the same name!!!
            """
        )
        # Examples of things left behind:
        # - In files on LCM VM: /isima/lcm/updated_resources/load-balancer.conf, and
        #     on load balancer VMs: /isima/bioslb/conf.d/load-balancer.conf,
        #     the following entries get left behind:
        #       "upstream webhook_tenant1" - 4 lines
        #       "location /integration/tenant1" - 9 lines
        #       "include /var/ext_resources/conf.d/lb-sql-tenant1.conf" - 1 line
        # - On load balancers: /isima/bioslb/conf.d/lb-sql-tenant1.conf
        # - Entries for this tenant in ports.yaml.


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
