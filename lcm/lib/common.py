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

import concurrent.futures
import os
import random
import re
import secrets
import time
import traceback
from collections.abc import Iterable
from functools import partial
from typing import Any, Dict
from typing import Iterable as IterableType
from typing import List, Tuple
from urllib.parse import urlparse

import invoke
import yaml
from fabric import connection
from lib.constants import (
    CERT_FILE,
    CONFIG_FILE,
    HOSTS_FILE,
    KEY_FILE,
    LOCAL_JOURNAL_PATH,
    RELATIVE_DEFAULT_CONFIG_FILE,
    REMOTE_JOURNAL_PATH,
    REQUIREMENTS_BY_ROLE,
)
from lib.errors import RemoteExecutionsError
from lib.log import Log


def is_valid_url(path):
    try:
        result = urlparse(path)
        return bool(result.scheme)
    except ValueError:
        return False, ""


def get_name_and_ip(host):
    if host is None:
        return f"localhost"
    if host["connection"] is None:
        return f"{host['name']} ({host['ip']}) - localhost"
    return f"{host['name']} ({host['ip']})"


def run_local(
    cmd: str, accepted_exit_codes: Iterable[int] = None, ignore_error: bool = False
) -> invoke.runners.Result:
    Log.trace(f"{cmd}")

    if accepted_exit_codes is None:
        accepted_exit_codes = []

    result = invoke.run(
        cmd, err_stream=Log.get_trace_file(None), out_stream=Log.get_trace_file(None), warn=True
    )

    if result.failed and result.return_code not in accepted_exit_codes and not ignore_error:
        raise RuntimeError(
            f"Local execution failed for command: {cmd} output:{result.stdout}"
            f" with exit code: {result.return_code}"
            f" with error: {result.stderr}\n {result}"
        )

    return result


def run_sudo_local(
    cmd, do_not_redirect_output=False, accepted_exit_codes=None
) -> invoke.runners.Result:
    Log.trace(f"{cmd}")

    if accepted_exit_codes is None:
        accepted_exit_codes = []

    if do_not_redirect_output:
        result = invoke.sudo(cmd, warn=True)
    else:
        result = invoke.sudo(
            cmd,
            err_stream=Log.get_trace_file(None),
            out_stream=Log.get_trace_file(None),
            warn=True,
        )

    if result.failed and result.return_code not in accepted_exit_codes:
        raise Exception(
            f"Local sudo execution failed for command: {cmd} output:{result.stdout}"
            f" with exit code: {result.return_code}"
            f" with error: {result.stderr}\n {result}"
        )

    return result


def run_remote(host, cmd, accepted_exit_codes=None, out_stream=None) -> invoke.runners.Result:
    Log.trace2(host, f"on {get_name_and_ip(host)}: {cmd}")

    if accepted_exit_codes is None:
        accepted_exit_codes = []
    if out_stream is None:
        out_stream = Log.get_trace_file(host)

    if (host is None) or (host["connection"] is None):
        result = invoke.run(
            cmd,
            err_stream=out_stream,
            out_stream=out_stream,
            warn=True,
        )
    else:
        conn = host["connection"]
        result = conn.run(
            cmd,
            err_stream=out_stream,
            out_stream=out_stream,
            warn=True,
        )

    if result.return_code != 0 and result.return_code not in accepted_exit_codes:
        raise RuntimeError(
            f"""
            Remote execution on {get_name_and_ip(host)} failed for command:
            {cmd}
            with exit code: {result.return_code}
            output:{result.stdout}
            error: {result.stderr}
            """
        )
    return result


def run_sudo_remote(host, cmd, accepted_exit_codes=None) -> invoke.runners.Result:
    Log.trace2(host, f"on {get_name_and_ip(host)}: {cmd}")

    if accepted_exit_codes is None:
        accepted_exit_codes = []

    if (host is None) or (host["connection"] is None):
        result = invoke.sudo(
            cmd,
            err_stream=Log.get_trace_file(host),
            out_stream=Log.get_trace_file(host),
            warn=True,
        )
    else:
        conn = host["connection"]
        result = conn.sudo(
            cmd,
            err_stream=Log.get_trace_file(host),
            out_stream=Log.get_trace_file(host),
            warn=True,
        )

    if result.return_code != 0 and result.return_code not in accepted_exit_codes:
        raise Exception(
            f"Remote sudo execution on {get_name_and_ip(host)} failed for command: {cmd}"
            f" with exit code: {result.return_code}"
            f" output:{result.stdout} with error: {result.stderr}"
        )
    return result


def get_file(host, source_file_abs_path, dest_dir):
    Log.trace2(host, f"{get_name_and_ip(host)}: {source_file_abs_path} to {dest_dir}")
    if (host is None) or (host["connection"] is None):
        return run_local(f"cp {source_file_abs_path} {dest_dir}")

    conn = host["connection"]
    result = conn.get(source_file_abs_path, dest_dir)
    return result


def put_file(host, source_file_abs_path, dest_dir):
    Log.trace2(host, f"{source_file_abs_path} to {get_name_and_ip(host)}: {dest_dir}")
    if (host is None) or (host["connection"] is None):
        return run_local(f"cp {source_file_abs_path} {dest_dir}")

    conn = host["connection"]
    result = conn.put(source_file_abs_path, dest_dir)
    return result


def deep_merge_dictionaries(baseline_dest, overlay_source):
    for key, _ in overlay_source.items():
        if (
            (key in baseline_dest)
            and isinstance(baseline_dest[key], dict)
            and isinstance(overlay_source[key], dict)
        ):
            deep_merge_dictionaries(baseline_dest[key], overlay_source[key])
        else:
            baseline_dest[key] = overlay_source[key]


def deep_add_dictionaries(baseline_dest, overlay_source):
    for key, _ in overlay_source.items():
        if (
            (key in baseline_dest)
            and isinstance(baseline_dest[key], dict)
            and isinstance(overlay_source[key], dict)
        ):
            deep_add_dictionaries(baseline_dest[key], overlay_source[key])
        else:
            baseline_dest[key] += overlay_source[key]


def load_yaml_file(filename):
    with open(filename, mode="r", encoding="UTF-8") as default_config_file:
        default_config = yaml.safe_load(default_config_file)
    return default_config


def save_yaml_file(filename, data):
    with open(filename, "w", encoding="UTF-8") as out_file:
        yaml.dump(data, out_file, default_flow_style=False)


def get_effective_config(input_config_file, default_config_file):
    default_config = load_yaml_file(default_config_file)
    Log.trace(f"default_config from file {default_config_file}:")
    Log.trace(str(default_config))

    input_config = load_yaml_file(input_config_file)
    Log.trace(f"input_config from file {input_config_file}:")
    Log.trace(str(input_config))

    deep_merge_dictionaries(default_config, input_config)
    Log.trace(f"Effective config:")
    Log.trace(str(default_config))
    return default_config


def get_lcm_path():
    return os.path.dirname(os.path.realpath(__file__)) + "/.."


def open_new_connection(host, gateway=None):
    user = None
    password = None
    destination = host["ip"]

    # The LCM machine is used as a gateway to create the initial connection to bi(OS) internal
    # nodes, which do not have the lcm_user created at the time. Thus we ignore the user field
    # in case it the connection uses a gateway.
    if not gateway and "user" in host:
        user = host["user"]
        Log.debug(f"Using user {user} for the login")
    if "password" in host:
        password = host["password"]
    if host["cloud"] == "gcp":
        destination = host.get("full_name", destination)
    host["connection"] = connection.Connection(
        destination, user=user, gateway=gateway, connect_kwargs={"password": password}
    )
    try:
        host["connection"].open()
    except Exception as err:
        raise RuntimeError(f"Failed to connect {host['name']} at {host['ip']} for {err}") from err
    Log.debug(f"Successfully opened connection to host {get_name_and_ip(host)}")


def validate_vm_counts(roles):
    for role, requirements in REQUIREMENTS_BY_ROLE.items():
        (min_hosts, max_hosts) = requirements
        if role not in roles:
            if min_hosts > 0:
                raise Exception(f"hosts file missing '{role}' role")
            continue

        role_count = 0
        names = []
        if isinstance(roles[role], int):
            role_count = roles[role]
        else:
            names = roles[role]
            role_count = len(roles[role])

        if role == "storage" and (role_count % 3):
            raise Exception(
                f"Storage node count can only be in multiples of 3, yet"
                f" {role_count} requested!"
            )

        if role_count < min_hosts:
            raise Exception(
                f"At least {min_hosts} entries expected for '{role}' role,"
                f" found {role_count}: {names}"
            )
        if role_count > max_hosts:
            raise Exception(
                f"At most {max_hosts} entries expected for '{role}' role,"
                f" found {role_count}: {names}"
            )


def validate_and_normalize_hosts(config, hosts_and_roles):
    Log.info("Validating hosts and connecting to them.")
    required_sections = ["hosts", "roles"]
    string_entry_members = ["ip"]

    try:
        for section in required_sections:
            if section not in hosts_and_roles:
                raise RuntimeError(f"hosts file missing '{section}' section")

        host_entries = hosts_and_roles["hosts"]
        if not isinstance(host_entries, dict):
            raise RuntimeError("Expected a dictionary of host entries in section 'hosts'")

        for name, entry in host_entries.items():
            if not isinstance(entry, dict):
                raise RuntimeError(
                    f"All entries in 'hosts' section should be dictionaries;"
                    f" for host '{name}', got entry {entry}"
                )
            for member in string_entry_members:
                if member not in entry:
                    raise RuntimeError(
                        f"Member '{member}' not present in host '{name}', entry {entry}"
                    )
                if not isinstance(entry[member], str):
                    raise RuntimeError(
                        f"Expected a string for member '{member}', got: {entry[member]}"
                    )

        roles = hosts_and_roles["roles"]
        if not isinstance(roles, dict):
            raise RuntimeError("Expected a dictionary in section 'roles'")

        validate_vm_counts(roles)

        for role in roles:
            names = roles[role]
            if not isinstance(names, list):
                raise RuntimeError(
                    f"Expected a list/array of host names for '{role}' role, found {names}"
                )
            for name in names:
                if name not in host_entries:
                    raise RuntimeError(
                        f"Role '{role}' refers to host name '{name}'"
                        f" which is not present in 'hosts' section"
                    )

    except Exception as exception:
        raise RuntimeError(f"hosts.yaml validation failed: {str(hosts_and_roles)}") from exception

    # Normalize (make it easy to access):
    # * Add cloud provider information to the node.
    # * Add the lcm machine public key to all nodes.
    # * Add a "name" member to each host entry.
    # * Replace arrays of host names with host entries for each role.
    # * For "lb" hosts if "public_ip" member is not present, set it equal to "ip".
    # * Check that the cluster DNS points to the public IPs of lb hosts.
    # * Open a connection to necessary host(s) and store them in the entries.
    # * Validate minimum specs and calculate memory / CPU distributions.

    clouds = []
    if "cloud" in hosts_and_roles:
        clouds.append(hosts_and_roles["cloud"])

    host_entries = hosts_and_roles["hosts"]
    for name, entry in host_entries.items():
        entry["name"] = name
        if "cloud" in entry and entry["cloud"] not in clouds:
            clouds.append(entry["cloud"])
        elif "cloud" not in entry:
            entry["cloud"] = hosts_and_roles["cloud"]

    host_entries = hosts_and_roles["hosts"]
    roles = hosts_and_roles["roles"]
    for role, _ in REQUIREMENTS_BY_ROLE.items():
        if role in roles:
            names = roles[role]
            role_host_entries = [host_entries[name] for name in names]
            roles[role] = role_host_entries

    # Set up connections to all hosts.
    for name, entry in host_entries.items():
        Log.debug(f"Opening connection to host {name} ({entry['ip']})")
        open_new_connection(entry)
        _gather_host_info(config, entry, roles)

    # Check that the cluster DNS points to the public IPs of lb hosts.
    public_ips = []
    for host in roles["lb"]:
        if "public_ip" not in host:
            host["public_ip"] = host["ip"]
        public_ips.append(host["public_ip"])
    config["public_ips"] = public_ips

    # Log.info(
    #     f"Checking whether cluster's DNS name {config['cluster_dns_name']} points to {public_ips}"
    # )
    # run_sudo_local("resolvectl flush-caches")
    # run_sudo_local("systemctl restart systemd-resolved")
    # (name, aliases, dns_ips) = socket.gethostbyname_ex(config["cluster_dns_name"])


def _power_of_2_upto(num):
    while num & (num - 1):
        num = num & (num - 1)
    return num


def if_not_auto(if_value, else_value):
    """Choose a value if it is not 'auto'"""
    return if_value if if_value != "auto" else else_value


def _gather_host_info(config: dict, host: dict, roles: dict):
    run_remote(host, "uname -n")
    run_remote(host, "uname -rv")
    result = run_remote(host, "nproc")
    cpu_count = int(result.stdout.strip())
    run_remote(host, "free -h")
    result = run_remote(host, "free --gibi | grep '^Mem:' | awk '{print $2}'")
    memory_gb = int(result.stdout.strip())
    run_remote(host, "lsblk")
    run_remote(host, "df -h")
    result = run_remote(host, f"find {config['data_dir_prefix']}* -maxdepth 0 -type d | wc -l")
    data_dir_count = int(result.stdout.strip())

    host["cpu_count"] = cpu_count
    host["memory_gb"] = memory_gb
    host["data_dir_count"] = data_dir_count

    # Locations of the data directories on the hosts are used by dbdozer.
    host_data_file_directories = config.setdefault("host_data_file_directories", {})
    host_data_file_directories[host["ip"]] = [
        f"{config['data_dir_prefix']}{dir_index + 1}"
        for dir_index in range(host["data_dir_count"])
    ]

    if host in roles["storage"]:
        storage_cpu_count = if_not_auto(config["storage_num_cpus"], cpu_count)
        if storage_cpu_count > cpu_count:
            raise RuntimeError(
                "Value of 'storage_num_cpus' in cluster_config.yaml exceeds available cpus"
            )
        storage_memory_gb = if_not_auto(config["storage_memory_gb"], memory_gb)
        if storage_memory_gb > memory_gb:
            raise RuntimeError(
                "Value of 'storage_memory_gb' in cluster_config.yaml"
                " exceeds available machine memory"
            )
    else:
        storage_cpu_count = cpu_count
        storage_memory_gb = memory_gb

    if storage_cpu_count <= 4:
        host["bios_storage_cpus"] = storage_cpu_count // 2
        host["bios_cpus"] = storage_cpu_count // 2
    elif storage_cpu_count <= 8:
        host["bios_storage_cpus"] = storage_cpu_count // 2
        host["bios_cpus"] = storage_cpu_count - host["bios_storage_cpus"]
    else:
        host["bios_storage_cpus"] = storage_cpu_count * 5 // 8
        host["bios_cpus"] = storage_cpu_count - host["bios_storage_cpus"]

    if host["bios_storage_cpus"] < 8:
        host["gc_threads"] = host["bios_storage_cpus"]
    elif host["bios_storage_cpus"] <= 10:
        host["gc_threads"] = host["bios_storage_cpus"] * 5 // 8
    else:
        host["gc_threads"] = host["bios_storage_cpus"] // 2

    host["bios_storage_heap_size"] = _power_of_2_upto(storage_memory_gb * 3 // 5)
    remaining_memory = storage_memory_gb - host["bios_storage_heap_size"]
    host["bios_storage_memory"] = host["bios_storage_heap_size"] + remaining_memory // 4
    host["bios_heap_size"] = remaining_memory // 3
    host["bios_memory"] = remaining_memory // 2


def replace_line_re(pattern, replacement, file_name):
    lines = []
    with open(file_name, encoding="UTF-8") as file:
        for item in file:
            updated_line = re.sub(pattern, str(replacement), item)
            lines.append(updated_line)
    with open(file_name, "w", encoding="UTF-8") as file:
        file.truncate()
        for line in lines:
            file.writelines(line)


def replace_line(keyword, replacement, file_name):
    lines = []
    with open(file_name, encoding="UTF-8") as file:
        for line in file:
            lines.append(line.replace(keyword, str(replacement)))
    with open(file_name, "w", encoding="UTF-8") as file:
        file.truncate()
        for line in lines:
            file.writelines(line)


def recalculate_config(config, hosts_and_roles):
    # Copy the information in hosts_and_roles into config, so that we don't have
    # to keep carrying around 2 different high level objects.
    config["hosts"] = hosts_and_roles["hosts"]
    config["roles"] = hosts_and_roles["roles"]
    if "cloud" in hosts_and_roles:
        config["cloud"] = hosts_and_roles["cloud"]

    if "region" in hosts_and_roles:
        config["region"] = hosts_and_roles["region"]

    if "cluster_name" not in config:
        config["cluster_name"] = config["cluster_dns_name"].split(".")[0]

    config["sub_roles"] = ["signal", "analysis", "rollup"]
    sub_role_count = len(config["sub_roles"])
    sub_role_servers = {sub_roles: [] for sub_roles in config["sub_roles"]}
    for index, node in enumerate(config["roles"]["storage"]):
        sub_role_index = index % sub_role_count
        sub_role_servers[config["sub_roles"][sub_role_index]].append(node["ip"])
        node["sub_role"] = config["sub_roles"][sub_role_index]

    config["sub_role_servers"] = sub_role_servers
    storage_ip_list = [host["ip"] for host in config["roles"]["storage"]]
    config["bios_seeds"] = ",".join(storage_ip_list)
    config["num_storage_nodes"] = len(storage_ip_list)
    if len(storage_ip_list) == 1:
        config["db_endpoint_snitch"] = "SimpleSnitch"
    else:
        config["db_endpoint_snitch"] = "GossipingPropertyFileSnitch"
    config["rewrite_bios_addresses"] = False


def download_file(config, file_name, host, dest_directory):
    """Downloads a file from the resource bucket
    (as a filesystem directory or a GoogleStorage bucket)."""
    prop = "resource_bucket"
    resource_url = config[prop]
    if not resource_url.endswith("/"):
        resource_url += "/"
    scheme_and_the_rest = resource_url.split(":", 2)
    if len(scheme_and_the_rest) < 2:
        raise RuntimeError(
            f"Resource bucket URL '{resource_url}' specified by property '{prop}'is missing scheme"
        )
    scheme = scheme_and_the_rest[0]
    supported_schemes = {"file", "gs"}
    if scheme not in supported_schemes:
        raise RuntimeError(
            f"Scheme {scheme} is unsupported for resource bucket URL specified by '{prop}'"
            " in cluster_config.yaml. Use one of {supported_schemes}"
        )

    full_url = "".join([resource_url, file_name])
    if scheme == "gs":
        if host:
            run_remote(host, f"gsutil cp {full_url} {dest_directory}/")
        else:
            run_local(f"gsutil cp {full_url} {dest_directory}/")
    else:  # file
        if not full_url.startswith("file://") or full_url[len("file://")] != "/":
            raise RuntimeError(
                f"Syntax error in resource bucket URL '{resource_url}'"
                " specified by property '{prop}' in cluster_config.yaml"
            )
        file_path = full_url[len("file://") :]
        if host:
            run_local(
                f"scp -o StrictHostKeyChecking=no {file_path} ubuntu@{host['ip']}:{dest_directory}/"
            )
        else:
            run_local(f"cp {file_path} {dest_directory}/")


def execute_on_hosts(
    function,
    friendly_string: str,
    hosts: IterableType[Dict[str, Any]],
    param1: Any,
    parallel: bool = True,
) -> List[Tuple[int, dict, Any, Exception]]:
    """Method to execute a function in parallel for multiple hosts.

    Args:
        function (function pointer): the function to execute.
            The function must take 3 input parameters:
                index (int): a number from 0 to (n-1) when executing on n hosts.
                host (LCM host object): the host on which to execute the function.
                param1 (Any): an additional parameter, e.g. config.
        friendly_string (str): this will be printed in logs and stdout.
        hosts (LCM host iterable): the hosts for which to execute the function.
        param1 (Any): the additional parameter to send to function.
        parallel (bool): whether to execute for each host in parallel. Default
                         is true.

    Returns:
        Tuple of index, host, result, and error.
        When an exection on a host was successful, result is the function's return value.


    Raises:
        Exception(s) raised by the given function.
    """
    hosts_list = list(hosts)
    results = []
    if parallel:
        num_threads = len(hosts_list)
        Log.info(f"=========> Parallel run: {num_threads} x '{friendly_string}' ...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(function, index, hosts_list[index], param1)
                for index in range(num_threads)
            ]
            for index, future in enumerate(futures):
                future.add_done_callback(
                    partial(
                        future_done_callback, friendly_string, index, hosts_list[index], results
                    )
                )
        check_results(friendly_string, results)
        Log.info("<========= Completed parallel run.")
    else:
        for index, host in enumerate(hosts_list):
            Log.info(
                f"- - - Sequential run '{friendly_string}' "
                f"for {index + 1}/{len(hosts_list)}: {get_name_and_ip(host)}"
            )
            try:
                result = function(index, host, param1)
                results.append((index, host, result, None))
            except Exception as error:
                Log.error(
                    f"Exception while running {friendly_string} on {host['name']}: {error}\n"
                    f"{traceback.format_exc()}"
                )
                results.append((index, host, None, error))
                break
        check_results(friendly_string, results)
    return results


def future_done_callback(friendly_string, index, host, results, future):
    """Handles the result of a submitted function"""
    got_exception = False
    try:
        result = future.result()
        results.append((index, host, result, None))
    except Exception as error:
        got_exception = True
        results.append((index, host, None, error))
        Log.error(
            f"Exception while running {friendly_string} on {host['name']}: {error}\n"
            f"{traceback.format_exc()}"
        )

    if got_exception:
        Log.error(f"    ------ thread {index} got exception for {get_name_and_ip(host)}!")
    else:
        Log.info(f"    ------ thread {index} completed for {get_name_and_ip(host)}.")


def check_results(friendly_string: str, results: List[Tuple[int, dict, Any, Exception]]):
    """Check results of function executions in method execute_on_hosts"""
    exception_host_list = []
    for index, host, _, error in results:
        if error is not None:
            exception_host_list.append(host["name"])
            Log.error(f"Exception on {index} - {get_name_and_ip(host)}:")
    if len(exception_host_list) > 0:
        Log.error(
            f"<========= Got {len(exception_host_list)} exceptions while running"
            f" '{friendly_string}' on hosts: {exception_host_list}"
        )
        raise RemoteExecutionsError(f"{friendly_string} failed", results)


def execute_wrapped(info, function):
    try:
        Log.info(f"Running {info}")
        function()
        Log.print_accumulated_errors()
    except Exception as err:
        Log.error(f"Fatal error: {''.join(traceback.format_exception(err))}")
        Log.fatal(str(err))


def initialize_lcm() -> dict:
    """Initialize LCM environment and returns config dict"""
    default_config_file = get_lcm_path() + RELATIVE_DEFAULT_CONFIG_FILE
    config = get_effective_config(CONFIG_FILE, default_config_file)
    hosts_and_roles = load_yaml_file(HOSTS_FILE)
    validate_and_normalize_hosts(config, hosts_and_roles)
    recalculate_config(config, hosts_and_roles)

    return config


def wait_for_bios_up(host, host_port):
    wait_for_server_up(host, f"{host_port}/bios/v1/version")


def wait_for_server_up(host, url):
    done = False
    tries = 0
    while not done:
        try:
            run_remote(host, f"curl -k -f {url} >/dev/null 2>&1")
            done = True
        except RuntimeError as exception:
            if tries >= 60:
                raise RuntimeError(f"url {url} not up after {5 * tries} seconds.") from exception
            time.sleep(5)
            tries += 1


def generate_and_copy_certs(dns_name, auth_file, wait, copy_dir):
    """Method to generate certs using certbot and copy them to the lcm path."""

    run_sudo_local(
        f"certbot certonly --force-renewal -d {dns_name},*.{dns_name} --agree-tos --email "
        f"domains@tieredfractals.com -n -v --dns-google "
        f"--dns-google-credentials {auth_file} "
        f"--dns-google-propagation-seconds {wait} ",
    )
    cert_filename = CERT_FILE.rsplit("/", maxsplit=1)[-1]
    key_filename = KEY_FILE.rsplit("/", maxsplit=1)[-1]
    run_sudo_local(f"cp /etc/letsencrypt/live/{dns_name}/fullchain.pem {copy_dir}/{cert_filename}")
    run_sudo_local(f"cp /etc/letsencrypt/live/{dns_name}/privkey.pem {copy_dir}/{key_filename}")
    run_sudo_local(f"chown $USER:$USER {copy_dir}/*.pem")
    run_local(f"chmod 600 {copy_dir}/{key_filename}")


def append_line_if_absent_sudo(host, file, line):
    run_remote(
        host, f"sudo grep -q -F '{line}' {file} 2>/dev/null || echo '{line}' | sudo tee -a {file}"
    )


def append_line_if_absent(host, file, line):
    run_remote(host, f"grep -q -F '{line}' {file} 2>/dev/null || echo '{line}' | tee -a {file}")


def append_line_if_absent_local(file, line):
    run_local(f"grep -q -F '{line}' {file} 2>/dev/null || echo '{line}' | sudo tee -a {file}")


def to_bash_profile(host, cmd):
    append_line_if_absent(host, "$HOME/.bash_profile", cmd)


def add_logs_alias(host: str, log_name: str, log_path: str):
    if not log_path.startswith("/"):
        log_path = "/var/log/" + log_path
    to_bash_profile(
        host,
        f"alias {log_name}=\"echo 'Tailing {log_path}' && sudo tail -F {log_path}\"",
    )
    to_bash_profile(host, f'alias {log_name}-vi="vi {log_path}"')


def _create_volume_init_command_start(mountpoint_or_prefix):
    return f"""
    set -e
    cat /etc/fstab | grep -v {mountpoint_or_prefix} | tee /tmp/.fstab.tmp
    """


def _create_volume_mount_command(volume, mountpoint, options):
    return f"""
    sudo mkdir -p {mountpoint}
    sudo chmod a+w {mountpoint}
    sudo mkfs.ext4 -m 0 -F -E lazy_itable_init=0,lazy_journal_init=0 {volume}
    echo UUID=`sudo blkid -s UUID -o value "{volume}"` {mountpoint} ext4 {options} 0 2 | tee -a /tmp/.fstab.tmp
    """


def _create_volume_init_command_end():
    return """
    sudo mv /tmp/.fstab.tmp /etc/fstab
    sudo mount -a
    """


def create_logs_volume_init_command(volume, mountpoint, options):
    return (
        _create_volume_init_command_start(mountpoint)
        + _create_volume_mount_command(volume, mountpoint, options)
        + _create_volume_init_command_end()
    )


def create_data_volume_init_command(data_volumes, data_dir_prefix, options):
    command = _create_volume_init_command_start(data_dir_prefix)

    for disk_number in range(1, 1 + len(data_volumes)):
        volume = data_volumes[disk_number - 1]
        mountpoint = data_dir_prefix + str(disk_number)
        command += _create_volume_mount_command(volume, mountpoint, options)

    command += _create_volume_init_command_end()
    return command


def get_container_resources_directory(
    host: str, container: str, destination: str = "/opt/bios/configuration"
) -> str:
    """Gets the resources directory for the existing container."""
    result = run_remote(
        host,
        "docker inspect --format='{{range $p := .Mounts}} "
        '{{if eq .Destination "' + destination + "\" }} {{.Source}} {{end}} {{end}}' " + container,
    )
    return result.stdout.strip()


# This function accepts a multiline string input which contains a column-labeled table. The first
# line should have the column names, separated by space, and the subsequent lines the corresponding
# values, also separated by space. Thus, the names or values cannot contain space in them. The
# output is a dictionary with the column names as the keys and the values corresponding to them in
# a list.
# Example:
# input =
# """
# IMAGE           NAMES
# bios:1.0.46     bios
# bios:1.0.45     bios_1.0.45
# """
# Returns:
# output = {"IMAGE" : ["bios:1.0.46", "bios:1.0.45"], "NAMES" : ["bios", "bios_1.0.45"]}
#
def parse_string_table(text: str):
    lines = text.splitlines()
    if not lines:
        return {}

    header = lines[0]
    data_lines = lines[1:]

    # Find column start positions by detecting space to non-space transitions
    col_starts = []
    prev = " "
    for i, current_char in enumerate(header):
        if current_char != " " and prev == " ":
            col_starts.append(i)
        prev = current_char
    col_starts.append(None)

    # Extract column names
    columns = [
        header[col_starts[i] : col_starts[i + 1]].rstrip() for i in range(len(col_starts) - 1)
    ]

    # Initialize result dictionary
    result = {col: [] for col in columns}

    # Fill column values
    for line in data_lines:
        for i, col in enumerate(columns):
            value = line[col_starts[i] : col_starts[i + 1]].rstrip()
            result[col].append(value)

    return result


# def parse_string_table(input_string):
#     table = input_string.splitlines()
#     output = {}
#     headings = []
#     for index, line in enumerate(table):
#         record = line.split()
#         if index == 0:
#             headings = record
#             output = {heading: [] for heading in headings}
#         else:
#             for column_index, entry in enumerate(record):
#                 output[headings[column_index]].append(entry)
#     return output


def load_options_file(filename):
    options = {}
    with open(filename, "r", encoding="UTF-8") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            if line and line[0] != "#":
                if "=" in line:
                    pair = line.split("=")
                    options[pair[0]] = pair[1]
                elif ":" in line:
                    pair = line.split(":")
                    options[pair[0]] = pair[1]

    return options


def update_options_file_inplace(filename, updated_options):
    updated_lines = []
    processed = {}

    for key in updated_options.keys():
        processed[key] = False

    with open(filename, encoding="UTF-8") as file:
        for line in file:
            line = line.strip()
            if line and line[0] != "#":
                if "=" in line:
                    delimiter = "="
                elif ":" in line:
                    delimiter = ":"
                else:
                    updated_lines.append(line)
                    continue

                key_name = line.split(delimiter)[0]
                # Make sure the removed keys are not added back.
                if key_name not in updated_options.keys():
                    continue

                processed[key_name] = True
                updated_lines.append(f"{key_name}{delimiter}{updated_options[key_name]}")
            else:
                updated_lines.append(line)

    # Append the new/renamed entries.
    # Does not support addition of dictionary elements.
    for key in updated_options.keys():
        if not processed[key]:
            updated_lines.append(f"{key}={updated_options[key]}")

    with open(filename, "w", encoding="UTF-8") as file:
        file.truncate()
        for line in updated_lines:
            file.writelines(line + "\n")


def find_version_string(candidates_str):
    """Given a list of strings, returns the first one which is a valid bios version

    Args:
        candidates (list): The list of candidate strings.

    Returns:
        str: The version
    """
    candidates = candidates_str.split(",")
    pattern = r"^\d+\.\d+\.\d+(-SNAPSHOT)?$"
    for candidate in candidates:
        if re.match(pattern, candidate):
            return candidate
    return ""


def calculate_latest_version(config):
    config["latest_bios_version"] = "Unknown"

    # Get the version corresponding to the "latest" bios.
    latest_bios_version = ""
    image_url = (
        f"{config['bios_container_registry']}/{config['bios_container_registry_project']}/bios"
    )

    result = run_local(f"gcloud container images list-tags {image_url}")
    bios_available_versions = parse_string_table(result.stdout)
    Log.trace(bios_available_versions)
    for tag_list in bios_available_versions["TAGS"]:
        if "latest" in tag_list:
            latest_bios_version = find_version_string(tag_list)
            Log.debug(f"Got latest version: {latest_bios_version}")
            break

    # In case no image tagged as latest, choose the first valid version.
    if latest_bios_version == "":
        index = 0
        while latest_bios_version == "" and index < len(bios_available_versions["TAGS"]):
            latest_bios_version = find_version_string(
                bios_available_versions["TAGS"][index].split(",")
            )
            index += 1

    latest_bios_version = latest_bios_version.strip()
    if latest_bios_version:
        config["latest_bios_version"] = latest_bios_version


def get_latest_version(config):
    if config["latest_bios_version"] == "NotCalculated":
        calculate_latest_version(config)
    if config["latest_bios_version"] == "Unknown":
        raise RuntimeError("Unable to calculate latest version of bios containers.")
    return config["latest_bios_version"]


def run_remote_journal(host, cmd, journal):
    """Runs a command on a remote host and writes the command to a journal file.

    Args:
        host (str): The host to run the command on.
        cmd (str): The command to run.
        journal (str): The journal file to write to.
    """
    run_local(f'echo "{cmd}" >> {LOCAL_JOURNAL_PATH}/{journal}.{host["name"]}.sh')
    run_remote(host, f'echo "{cmd}" >> {REMOTE_JOURNAL_PATH}/{journal}.sh')
    run_remote(host, cmd)


def get_resources_path(config: dict, prop: str) -> str:
    """Retrieves a resource pathname from a config dict.

    If the property value is a full path, the value is returned as is as the path name.
    If the property value is a relative path, the path name would be
    config['isima_base_path']/config[property]

    Args:
        config (dict): The configuration dict
        prop (str): Property name
    Returns:
        str: Resource path name
    """
    log_path = config[prop]
    if log_path.startswith("/"):
        return log_path
    return config["isima_base_path"] + "/" + log_path


def get_log_path(config: dict, prop: str) -> str:
    """Retrieves a log pathname from a config dict.

    If the property value is a full path, the value is returned as is as the path name.
    If the property value is a relative path, the path name would be
    config['log_base_path']/config[property]

    Args:
        config (dict): The configuration dict
        prop (str): Property name
    Returns:
        str: Log path name
    """
    log_path = config[prop]
    if log_path.startswith("/"):
        return log_path
    return config["log_base_path"] + "/" + log_path


def get_db_data_dir_numbers(host: dict, config: dict) -> List[int]:
    """Gets DB data directory numbers.

    If start and num_disks are specified, the method returns their specifying range.
    Otherwise, all available numbers in host['data_dir_count'] are returned.
    """
    num_available_disks = host["data_dir_count"]
    if config["data_disk_number_start"] != "auto" and config["num_data_disks"] != "auto":
        range_from = config["data_disk_number_start"]
        range_to = range_from + config["num_data_disks"]
        if range_from <= 0:
            raise RuntimeError("Property data_dir_start must be 1 or grater")
        if range_to > num_available_disks + 1:
            raise RuntimeError("Property data_dir_start + num_data_disks are out of range")
        return list(range(range_from, range_to))
    return list(range(1, 1 + host["data_dir_count"]))


def get_cluster_dns_name_port(config: dict) -> str:
    cluster_dns_name = config["cluster_dns_name"]
    if config["lb_https_port"] == 443:
        return cluster_dns_name
    return f"{cluster_dns_name}:{config['lb_https_port']}"


def generate_password(length: int) -> str:
    """Generates a random strong password."""
    if length < 8:
        raise RuntimeError("password length must be at least 8")

    digits = "0123456789"
    lower_cases = "abcdefghijklmnopqrstuvwxyz"
    upper_cases = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    symbols = "!@^*()_+-=<>./"
    # several symbols have issues in deli config. removing them temporarily: %&|#$
    # symbols = "!@#$%^&*()_+-=<>./|"
    all_chars = digits + lower_cases + upper_cases + symbols

    chars = [
        secrets.choice(digits),
        secrets.choice(lower_cases),
        secrets.choice(upper_cases),
        secrets.choice(symbols),
    ]
    for _ in range(length - 4):
        chars.append(secrets.choice(all_chars))
    random.shuffle(chars)
    return "".join(chars)
