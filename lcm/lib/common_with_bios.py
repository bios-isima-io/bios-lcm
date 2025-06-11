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

import bios
from bios.models.app_type import AppType
from lib.log import Log


def create_bios_session(config, user, password):
    Log.debug(f"bi(OS) login to cluster {config['cluster_dns_name']}, user {user}")
    session = bios.login(
        f"https://{config['cluster_dns_name']}:{config['lb_https_port']}",
        user,
        password,
        "LCM",
        AppType.ADHOC,
    )
    return session


def create_bios_session_system(config):
    return create_bios_session(config, "systemadmin@isima.io", config["systemadmin_password"])
