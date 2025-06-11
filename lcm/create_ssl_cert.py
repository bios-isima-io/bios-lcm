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
import sys

from lib.common import execute_wrapped, generate_and_copy_certs, run_sudo_local
from lib.log import Log


def create_ssl_cert(dns_name, auth_file, timeout):
    Log.info(f"Creating a new SSL certificate for DNS name: {dns_name}")
    lcm_dir = os.environ["HOME"] + "/lcm"
    os.system(f"mkdir -p {lcm_dir}/{dns_name}")

    generate_and_copy_certs(dns_name, auth_file, timeout, lcm_dir)

    run_sudo_local(f"cp {lcm_dir}/*.pem {lcm_dir}/{dns_name}/")

    Log.marker(f"Completed creating SSL certificate; files copied to {lcm_dir}")


def main():
    print_help = False
    if len(sys.argv) < 3:
        print_help = True
    else:
        first_arg = sys.argv[1]
        if first_arg in ["--help", "-h"]:
            print_help = True

    if print_help:
        print(
            f"""Usage: {sys.argv[0]} <DNS name> <GCP creds file> [timeout (seconds)] [verbose]

                timeout: time in seconds to wait for dns propagation, defaults to 15 seconds
                verbose: optionally print verbose logs
        """
        )
    else:
        dns_name = sys.argv[1]
        auth_file = sys.argv[2]
        timeout = 15
        if len(sys.argv) >= 4:
            if sys.argv[3] == "verbose":
                Log.set_verbose_output(True)
            elif sys.argv[3] == "timeout":
                timeout = sys.argv[4]
                if len(sys.argv) >= 6 and sys.argv[5] == "verbose":
                    Log.set_verbose_output(True)

        create_ssl_cert(dns_name, auth_file, timeout)


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
