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

ISIMA_BASE_PATH = "/isima"
LCM_ROOT = f"{ISIMA_BASE_PATH}/lcm"
DATA_DIR = f"{LCM_ROOT}/env"
LCM_DIR = f"{LCM_ROOT}/lcm"
IMAGES_DIR = f"{LCM_ROOT}/images"
CACHE_DIR = f"{LCM_ROOT}/cache"

HOSTS_FILE = f"{DATA_DIR}/hosts.yaml"
CONFIG_FILE = f"{DATA_DIR}/cluster_config.yaml"
CERT_FILE = f"{DATA_DIR}/web.cert.pem"
KEY_FILE = f"{DATA_DIR}/web.key.pem"

# Trino specific constants
SERVER_CERT_FILE = f"{DATA_DIR}/server.cert.pem"
NODE_ID = "NODE_ID"
IS_COORDINATOR = "IS_COORDINATOR"
IS_COORDINATOR_ALSO_WORKER = "IS_COORDINATOR_ALSO_WORKER"
HTTPS_PORT = "HTTPS_PORT"
HTTP_PORT = "HTTP_PORT"
DISCOVERY_URI = "DISCOVERY_URI"
NODE_ENVIRONMENT = "NODE_ENVIRONMENT"
SHARED_SECRET = "SHARED_SECRET"
WEB_UI_ENABLED = "WEB_UI_ENABLED"

CREDS_FILE = f"{LCM_DIR}/bios_image_reader_key.json"
PORTS_FILE = f"{DATA_DIR}/ports.yaml"

RELATIVE_DEFAULT_CONFIG_FILE = "/default_configs/default_cluster_config.yaml"

LOCAL_RES_PATH_BASE = f"{LCM_ROOT}/updated_resources"
LOCAL_JOURNAL_PATH = f"{ISIMA_BASE_PATH}/journal"
REMOTE_JOURNAL_PATH = f"{ISIMA_BASE_PATH}/journal"
BIOS_CONFIGS_PATH = f"{LCM_DIR}/bios_configs"
BIOS_SERVICES_PATH = f"{BIOS_CONFIGS_PATH}/services"

LCM_LOGS_PATH = f"{LCM_ROOT}/log"
UPGRADE_RESOURCES_BASE_PATH = f"{LCM_ROOT}/upgrade"
UPGRADE_CONFIGS_PATH = f"{DATA_DIR}/upgrade_configs"
BIOS_RESOURCES_COMPLETION_MARKER = "resource_set_complete_marker"
BIOS_CONTAINER_READY_MARKER_PREFIX = "ready_to_use_marker"

AWS_USER = "ubuntu"

DEFAULT_INFRA_CONFIG_PATH = "/default_configs/default_infra_config.yaml"

PLACEHOLDER_BOOT_SCRIPT = """#!/bin/bash
echo Hello World!
"""
# Tuple elements are: min hosts, max hosts
REQUIREMENTS_BY_ROLE = {
    "lcm": (1, 1),
    "storage": (3, 12),
    "lb": (1, 3),
    "compute": (0, 20),
    "load": (0, 3),
    "jupyter_hub": (0, 1),
}

# Path in the LCM machine where we place server app integration tools like the trino client
TRINO_FOLDER = f"{LCM_ROOT}/trino"

# LB anchors
BIOS_APPS_UPSTREAMS_ANCHOR = "BIOS_APPS_UPSTREAMS_ANCHOR"
BIOS_APPS_LOCATIONS_ANCHOR = "BIOS_APPS_LOCATIONS_ANCHOR"

# Container types
CONTAINER_T_BIOS = "bios"
CONTAINER_T_STORAGE = "bios-storage"
CONTAINER_T_LB = "bioslb"
CONTAINER_T_INTEGRATIONS = "bios-integrations"
CONTAINER_T_SQL = "bios-sql"
CONTAINER_T_DEV = "bios-devtools"
CONTAINER_T_MAINTAINER = "dbdozer"
CONTAINER_T_LOAD = "load"
