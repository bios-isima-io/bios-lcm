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
"""Provides a provisioner for a cloud"""

from typing import List

from lib.provisioner import Provisioner
from lib.provisioner_aws import AwsProvisioner
from lib.provisioner_gcp import GcpProvisioner


class UnknownCloudTypeError(RuntimeError):
    """Exception thrown to indicate that a specified cloud type is unknown"""

    def __init__(self, cloud):
        self.cloud = cloud


def create_provisioners(
    cloud: str,
    operation: str,
    infra_config_file: str,
    credential_file: str,
    hosts_file: str,
) -> List[Provisioner]:
    """Creates provisioners for specified clouds"""
    is_cred_gcp = operation == "update_dns_records"
    if cloud == "aws":
        return [
            AwsProvisioner(
                operation, infra_config_file, credential_file, False, hosts_file, is_cred_gcp
            )
        ]

    if cloud == "gcp":
        return [GcpProvisioner(operation, infra_config_file, credential_file, False, hosts_file)]

    if cloud != "multi":
        raise UnknownCloudTypeError(cloud)

    cred_files = credential_file.split(",")

    provision_aws = AwsProvisioner(
        operation, infra_config_file, cred_files[0], True, hosts_file, is_cred_gcp
    )
    provision_gcp = GcpProvisioner(operation, infra_config_file, cred_files[1], True, hosts_file)

    return [provision_aws, provision_gcp]
