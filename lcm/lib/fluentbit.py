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

from .common import download_file, execute_on_hosts, get_name_and_ip, run_remote
from .log import Log


def configure_fluentbit(config):
    """Configures FluentBit"""
    Log.info("Configuring fluentbit for cluster.")
    execute_on_hosts(
        configure_fluentbit_on_host,
        "Configure fluentbit",
        config["hosts"].values(),
        config,
    )


def configure_fluentbit_on_host(index, host, config):
    """Configures FluentBit for the host"""
    del index
    fluentbit_filename = config["fluentbit_filename"]
    if not fluentbit_filename:
        Log.error(
            f"(for {host['name']}) Fluentbit installation file location is not specified"
            " in cluster_config.yaml, skipping the installation."
        )
        return
    download_file(config, fluentbit_filename, host, "/tmp/")

    email = "observe_writer@isima.io"
    password = config["observe_writer_password"]
    Log.debug(f"Setting up fluentbit agent on host: {get_name_and_ip(host)}")
    run_remote(
        host,
        f"export LOGDIR_NGINX=/var/log/bioslb && "
        f"export WEBHOOK_PATH=/integration/_system/nodestats && "
        f"export DOMAIN_NAME={config['cluster_dns_name']} && "
        f"export USER={email} && "
        f'export PASSWORD="{password}" && '
        f"bash /tmp/{fluentbit_filename}",
    )
