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
from typing import List, Tuple

from lib.common import execute_wrapped
from lib.log import Log
from lib.provisioner import Provisioner
from lib.provisioner_factory import UnknownCloudTypeError, create_provisioners

SUPPORTED_OPERATIONS = [
    "list",
    "provision",
    "obliterate",
    "demolish",
    "update_dns_records",
    "initialize_account",
]


def make_provisioners(args) -> Tuple[List[Provisioner], str]:
    if len(args) == 0 or args[1] in {"help", "--help"}:
        usage(args[0])
    if len(args) < 4:
        usage(args[0])

    args_index = 1
    cloud = args[args_index]
    args_index += 1
    operation = args[args_index]
    args_index += 1
    interactive = True
    if operation in {"demolish", "obliterate"} and args[args_index] == "-y":
        interactive = False
        args_index += 1
    if args_index >= len(sys.argv):
        usage(args[0])
    infra_config_file = sys.argv[args_index]
    args_index += 1
    infra_creds_file = ""
    hosts_file = ""

    if operation not in SUPPORTED_OPERATIONS:
        print(f"Unknown sub command: {operation}")
        usage(args[0])

    if operation == "initialize_account":
        if cloud != "aws":
            print("Subcommand {operation} is not supported for cloud type {cloud}")
            usage(args[0])
    else:
        if args_index >= len(args):
            usage(args[0])
        infra_creds_file = args[args_index]
        args_index += 1

    if operation == "update_dns_records":
        if args_index >= len(args):
            usage(args[0])
        hosts_file = args[args_index]
        args_index += 1

    if args_index < len(args) and sys.argv[args_index] == "verbose":
        Log.set_verbose_output(True)

    try:
        provisioners = [
            p.set_interactive(interactive)
            for p in create_provisioners(
                cloud, operation, infra_config_file, infra_creds_file, hosts_file
            )
        ]
    except UnknownCloudTypeError as err:
        print(f"Error: Cloud type {err.cloud} is unsupported")
        sys.exit(1)

    return provisioners, operation


def usage(script_path: str):
    """Print usage and exit"""
    command = os.path.basename(script_path)
    print(
        f"""

    Usage:
        {command} cloud_provider provision <infra config yaml file> <cred file> [verbose]
                : provision infrastructure (including VMs and storage) for a bi(OS) cluster on the
                  given cloud platform.

                A hosts.yaml file is created in $HOME/lcm directory and copied to the
                /isima/lcm/env directory of a newly created small VM (designated to be the new LCM
                VM). If the $HOME/lcm directory contains SSL certificate and key files named
                web.cert.pem and web.key.pem, they will be copied to the newly created LCM VM into
                /isima/lcm/env directory with names web.cert.pem and web.key.pem respectively.
                These files can subsequently be used to install a bi(OS) cluster.

        {command} cloud_provider list <infra config yaml file> <cred file> [verbose]
                : List VMs in the project with names having the prefix specified in the config
                  file for the given cloud platform.

        {command} cloud_provider demolish [-y] <infra config yaml file> <cred file> [verbose]
                : Completely terminate and delete all resources provisioned using the provided
                  config for the given cloud platform. The -y option disables interactions.

        {command} cloud_provider update_dns_records <infra config yaml file> <GCP creds file>
                      <hosts.yaml file> [verbose]
                : Update DNS record(s) for the cluster DNS name to point to public IPs of LB nodes.

        {command} cloud_provider initialize_account <infra config yaml file> [verbose]
                : Create network resources for bi(OS) on the cloud. Only AWS supported for now.

        verbose: optionally print verbose logs

        NOTE: Use 'multi' as the cloud_provider for multi_cloud, and pass cred files separated
              by a comma (',') in alphabetic order of the cloud provider name.

    For detailed instructions, see lcm/README.md
        """
    )
    sys.exit(1)


def main():
    """Provisioning main program."""
    provisioners, operation = make_provisioners(sys.argv)

    if operation == "provision" and len(provisioners) > 1:
        provisioner_aws = provisioners[0]
        provisioner_gcp = provisioners[1]

        provisioner_aws.provision_core()
        provisioner_gcp.provision(provisioner_aws.hosts_and_roles)
    else:
        for provisioner in provisioners:
            provisioner.execute()


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
