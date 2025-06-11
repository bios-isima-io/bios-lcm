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
from datetime import datetime

from lib.common import (
    execute_on_hosts,
    execute_wrapped,
    generate_and_copy_certs,
    get_container_resources_directory,
    initialize_lcm,
    put_file,
    run_remote,
    run_sudo_remote,
)
from lib.constants import CERT_FILE, DATA_DIR, KEY_FILE
from lib.log import Log


def renew_ssl_cert(config, auth_file, wait):
    dns_name = config["cluster_dns_name"]
    Log.info(f"Updating SSL certificate for DNS name: {dns_name}")
    Log.debug(f"To see details: logs-lcm-full-localhost")
    generate_and_copy_certs(dns_name, auth_file, wait, DATA_DIR)
    Log.debug(f"Completed generating new SSL certificate; files copied to {DATA_DIR}")
    distribute_certs(config)


def distribute_certs(config):
    execute_on_hosts(
        distribute_certs_to_host,
        "Distribute new certificate",
        config["roles"]["lb"],
        config,
        parallel=False,
    )


def distribute_certs_to_host(index, host, config):
    del index, config

    destination_path = get_container_resources_directory(host, "bioslb", "/var/ext_resources")

    folder_name = f"old-certs-{datetime.today().strftime('%Y-%m-%d-%Hh-%Mm-%Ss')}"
    Log.info(f"Creating a backup of old certificate to {destination_path}/{folder_name}")
    run_remote(host, f"mkdir -p {destination_path}/{folder_name}")
    cert_filename = CERT_FILE.rsplit("/", maxsplit=1)[-1]
    key_filename = KEY_FILE.rsplit("/", maxsplit=1)[-1]
    run_remote(
        host,
        f"[ ! -f {destination_path}/{cert_filename} ] || \
        mv {destination_path}/{cert_filename} {destination_path}/{folder_name}",
    )
    run_remote(
        host,
        f"[ ! -f {destination_path}/{key_filename} ] || \
            mv {destination_path}/{key_filename} {destination_path}/{folder_name}",
    )

    Log.info(f"Copying renewed certificate")
    put_file(host, CERT_FILE, destination_path)
    put_file(host, KEY_FILE, destination_path)
    run_remote(host, f"chmod 600 {destination_path}/{key_filename}")

    Log.info(f"Restarting bioslb container")
    run_sudo_remote(host, "docker restart bioslb")
    time.sleep(15)


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
            f"""Usage: {sys.argv[0]} <GCP creds file> [wait (seconds)] [verbose]
                : Update certificates for the domain name and distribute them to the LB nodes.

                wait: time in seconds to wait for dns propagation, defaults to 15 seconds
                verbose: optionally print verbose logs

                Ensure the following files are up-to-date in /isima/lcm/env directory:
                    * hosts.yaml
                    * cluster_config.yaml

        """
        )

    else:
        auth_file = sys.argv[1]
        wait = 15
        if len(sys.argv) >= 3:
            if sys.argv[2] == "verbose":
                Log.set_verbose_output(True)
            elif sys.argv[2] == "wait":
                wait = sys.argv[3]
                if len(sys.argv) >= 5 and sys.argv[4] == "verbose":
                    Log.set_verbose_output(True)

        config = initialize_lcm()

        renew_ssl_cert(config, auth_file, wait)
        Log.marker(f"Certificate Update complete!")


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
