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

import readline  # pylint: disable=unused-import
import sys

from lib.common import execute_wrapped, initialize_lcm, run_remote


def interactive_session(config):
    print("Welcome to LCM interactive session")
    try:
        finished = False
        while not finished:
            finished = get_hosts_and_run_commands(config)
    except KeyboardInterrupt:
        return


def get_hosts_and_run_commands(config):
    (group_str, hosts) = select_hosts(config)
    if hosts is None:
        return True
    finished = False
    while not finished:
        finished = get_and_run_command(group_str, hosts)
    return False


def get_and_run_command(group_str, hosts):
    print()
    try:
        command = input(f"{group_str}> ")
    except EOFError:
        return True
    except KeyboardInterrupt:
        return False

    for host in hosts:
        print()
        dashes = "---------------------------------------------------------------"
        print(f"{dashes} On host {host['name']} {dashes}")
        try:
            run_remote(host, command, out_stream=sys.stdout)
        except Exception:
            pass
    return False


def select_hosts(config):
    print()
    print("Host groups:")
    print(f"    all")
    for role in config["roles"].keys():
        print(f"    {role}")
    print("Hosts:")
    for host in config["hosts"].keys():
        print(f"    {host}")
    print()

    try:
        group_str = input("Enter host group or host name (Ctrl-D to exit): ")
    except EOFError:
        return (None, None)
    except KeyboardInterrupt:
        return (None, None)

    hosts = []
    if group_str == "all":
        hosts = config["hosts"].values()
    elif group_str in config["roles"].keys():
        hosts = config["roles"][group_str]
    elif group_str in config["hosts"].keys():
        hosts = [config["hosts"][group_str]]
    else:
        print("Invalid group or host name!")
        sys.exit(1)
    hosts = list(hosts)

    print(f"Selected hosts:")
    for host in hosts:
        print(f"    {host['name']}")
    print()
    return (group_str, hosts)


def main():
    config = initialize_lcm()
    interactive_session(config)


if __name__ == "__main__":
    execute_wrapped(sys.argv, main)
