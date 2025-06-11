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

import json
import os
import time

import googleapiclient.discovery
from fabric import connection
from lib.common import (
    append_line_if_absent_sudo,
    create_data_volume_init_command,
    create_logs_volume_init_command,
    open_new_connection,
    put_file,
    run_local,
    run_remote,
    run_sudo_remote,
)
from lib.constants import PLACEHOLDER_BOOT_SCRIPT
from lib.log import Log
from lib.provisioner import Provisioner


class GcpProvisioner(Provisioner):
    """Provisioner implementation for AWS."""

    def __init__(
        self,
        operation,
        infra_config_file,
        infra_creds_file,
        is_multi_cloud: bool,
        hosts_file_name: str,
    ):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = infra_creds_file
        super().__init__(
            "gcp", operation, infra_config_file, infra_creds_file, is_multi_cloud, hosts_file_name
        )

        # Verify that the creds file looks compatible.
        Log.debug(f"Doing basic validation of creds file {self.key_file}")
        with open(self.key_file, "r", encoding="UTF-8") as creds_file:
            try:
                creds = json.load(creds_file)
            except Exception as exception:
                raise RuntimeError(
                    f"GCP creds file {self.key_file} should be in json format."
                ) from exception
        expected = "private_key"
        if expected not in creds:
            raise RuntimeError(f"GCP: expected {self.key_file} to contain json key {expected}.")

        self.config["regions"] = self.config["gcp_regions"]
        self.config["region"] = self.config["regions"][self.config["region_index"]]
        self.config["vm_type"] = self.config["gcp_vm_type"]
        self.config["vm_count"] = self.config["gcp_vm_count"]

        if self.config["vpc_name"] == "default":
            self.config["network"] = "global/networks/default"
        else:
            self.config["network"] = (
                f"projects/{self.config['gcp_project']}/global/networks/{self.config['vpc_name']}"
            )

        self.compute = googleapiclient.discovery.build("compute", "v1")
        self.user_name = self.config["lcm_user"]

        # Assumes AWS nodes provisioned before GCP.
        if is_multi_cloud:
            self.config["vm_done"] = self.config["aws_vm_count"]

        run_local(f"gcloud auth activate-service-account --key-file={self.key_file}")

    def connect_to_host(self, full_name):
        return connection.Connection(full_name)

    def make_zone(self, suffix):
        return f"{self.config['region']}-{suffix}"

    def set_up_vm_properties(self):
        self.config["vm_type"]["compute"]["startup_script"] = self.config["vm_type"]["lcm"][
            "startup_script"
        ] = self.config["vm_type"]["lb"]["startup_script"] = PLACEHOLDER_BOOT_SCRIPT

        use_nvme_for_log = self.config["vm_type"]["storage"]["use_nvme_for_log"]
        num_nvme_disks = self.config["vm_type"]["storage"]["num_nvme_disks"]
        log_disk_num = num_nvme_disks
        num_storage_nvme = num_nvme_disks

        log_disk_name = "/dev/sdb"
        log_mount_options = "defaults"

        if use_nvme_for_log:
            Log.info("Using nvme storage for logs")

            log_disk_name = f"/dev/nvme0n{log_disk_num}"
            log_mount_options = "discard," + log_mount_options

            num_storage_nvme -= 1

        data_volumes = []
        for disk_number in range(1, 1 + num_storage_nvme):
            data_volumes.append(f"/dev/nvme0n{disk_number}")
        boot_script = f"""
        #!/bin/bash

        echo Hello World!

        if test ! -f /mnt/disks/lcm_volumes_setup_done; then
            {create_logs_volume_init_command(log_disk_name, '/mnt/disks/disk1', log_mount_options)}
            {create_data_volume_init_command(data_volumes, '/mnt/disks/data', "discard,defaults")}
            touch /mnt/disks/lcm_volumes_setup_done
        fi
        """

        self.config["vm_type"]["storage"]["startup_script"] = boot_script

    def verify_setup(self):
        Log.info("Checking whether gcloud is initialized correctly.")
        try:
            run_local(f"gcloud compute config-ssh --project {self.config['gcp_project']}")
        except Exception as exception:
            raise RuntimeError(
                "gcloud is not configured with valid credentials. Run 'gcloud auth login'."
            ) from exception

    def get_vms(self, zone, vm_name, is_prefix):
        """
        This method gets all the VMs from GCP with the given name pattern.
        vm_name_filter can be of the form "example_name" or "example_name_prefix*".
        """
        out_vms = []
        Log.debug(f"Looking for VMs in zone {zone} with name {vm_name} is_prefix {is_prefix}")
        result = (
            self.compute.instances()  # pylint: disable=no-member
            .list(project=self.config["gcp_project"], zone=zone)
            .execute()
        )
        if "items" in result:
            vms = result["items"]
            for virtual_machine in vms:
                if is_prefix:
                    if virtual_machine["name"].startswith(vm_name):
                        Log.debug(virtual_machine["name"])
                        out_vms.append(virtual_machine)
                else:
                    if virtual_machine["name"] == vm_name:
                        Log.debug(virtual_machine["name"])
                        out_vms.append(virtual_machine)

        return out_vms

    def wait_for_operation(self, operation):
        zone = os.path.basename(operation["zone"])
        target = os.path.basename(operation["targetLink"])
        Log.debug(
            f"Waiting for operation to finish:"
            f" zone {zone} {operation['operationType']}: {target} ..."
        )
        tries = 0
        while True:
            result = (
                self.compute.zoneOperations()  # pylint: disable=no-member
                .get(project=self.config["gcp_project"], zone=zone, operation=operation["name"])
                .execute()
            )

            if result["status"] == "DONE":
                Log.debug("Wait operation completed.")
                if "error" in result:
                    raise RuntimeError(result["error"])
                return result
            if tries >= self.config["gcp_operations_wait_time_secs"]:
                raise RuntimeError(
                    f"GCP operations did not complete even after waiting for"
                    f" {self.config['gcp_operations_wait_time_secs']} seconds!"
                )
            time.sleep(1)

    def create_vm(
        self,
        vm_name,
        zone,
        machine_type,
        os_disk_size_gb,
        log_disk_size_gb,
        use_nvme_for_log,
        nvme_disk_size_gb,
        num_nvme_disks,
        startup_script,
    ):
        # Check whether a VM with the same name already exists.
        vm_details = self.get_vms(zone, vm_name, False)
        if vm_details:
            raise RuntimeError(f"A vm with name {vm_name} already exists!")

        if num_nvme_disks not in [0, 1, 2, 4, 8, 16, 24]:
            raise RuntimeError(
                f"Number of local SSDs for VM {vm_name} should be one of "
                f"[0, 1, 2, 4, 8, 16, 24], while [{num_nvme_disks}] is requested.!"
            )

        print_log_disk_size_gb = log_disk_size_gb
        if use_nvme_for_log:
            print_log_disk_size_gb = nvme_disk_size_gb

        Log.info(
            f"Creating vm with name {vm_name} in zone {zone}, machine_type {machine_type},"
            f" os_disk_size_gb {os_disk_size_gb}, log_disk_size_gb {print_log_disk_size_gb},"
            f" num_nvme_disks {num_nvme_disks}"
        )
        image_response = (
            self.compute.images()  # pylint: disable=no-member
            .getFromFamily(
                project=self.config["os_image_project"], family=self.config["os_image_family"]
            )
            .execute()
        )
        source_disk_image = image_response["selfLink"]

        # Configure the machine
        machine_type_path = f"zones/{zone}/machineTypes/{machine_type}"

        config = {
            "name": vm_name,
            "machineType": machine_type_path,
            # Specify the boot disk and the image to use as a source.
            "disks": [
                {
                    "boot": True,
                    "autoDelete": True,
                    "initializeParams": {
                        "sourceImage": source_disk_image,
                        "diskSizeGb": os_disk_size_gb,
                        "diskName": f"{vm_name}-os-disk",
                    },
                },
            ],
            "networkInterfaces": [{"network": self.config["network"]}],
            "metadata": {
                "items": [
                    {  # Startup script is automatically executed by the vm upon startup.
                        "key": "startup-script",
                        "value": startup_script,
                    },
                ]
            },
            "tags": {"items": []},
        }
        if log_disk_size_gb > 0 and not use_nvme_for_log:
            log_disk = {
                "type": "PERSISTENT",
                "mode": "READ_WRITE",
                "initializeParams": {
                    "diskType": f"zones/{zone}/diskTypes/pd-ssd",
                    "diskSizeGb": log_disk_size_gb,
                    "diskName": f"{vm_name}-log-disk",
                },
                "autoDelete": True,
                "interface": "SCSI",
                "kind": "compute#attachedDisk",
                "deviceName": f"{vm_name}-log-disk",
            }
            config["disks"].append(log_disk)

        for disk_number in range(1, num_nvme_disks + 1):
            nvme_config = {
                "type": "SCRATCH",
                "mode": "READ_WRITE",
                "initializeParams": {
                    "diskType": f"zones/{zone}/diskTypes/local-ssd",
                    "diskSizeGb": nvme_disk_size_gb,
                },
                "autoDelete": True,
                "interface": "NVME",
                "kind": "compute#attachedDisk",
                "deviceName": f"{vm_name}-data-disk{disk_number + 1}",
            }
            config["disks"].append(nvme_config)

        config["networkInterfaces"][0]["accessConfigs"] = [
            {"type": "ONE_TO_ONE_NAT", "name": "External NAT"}
        ]

        if "lb-" in vm_name:
            config["tags"]["items"].append("allow-https")

        return (
            self.compute.instances()  # pylint: disable=no-member
            .insert(project=self.config["gcp_project"], zone=zone, body=config)
            .execute()
        )

    def create_vm_instances(self, vm_names, zones, vm_specs):
        operations = []

        for vm_name, zone in zip(vm_names, zones):
            use_nvme_for_log = False
            if "use_nvme_for_log" in vm_specs.keys():
                use_nvme_for_log = vm_specs["use_nvme_for_log"]

            operation = self.create_vm(
                vm_name,
                zone,
                vm_specs["machine_type"],
                vm_specs["os_disk_size_gb"],
                vm_specs["log_disk_size_gb"],
                use_nvme_for_log,
                vm_specs["nvme_disk_size_gb"],
                vm_specs["num_nvme_disks"],
                vm_specs["startup_script"],
            )
            if operation:
                operations.append(operation)

        return operations

    def confirm_instance_creations(self, provisioned_instances):
        Log.info("Waiting for GCP operations to complete ...")
        try:
            for operation in provisioned_instances:
                self.wait_for_operation(operation)
            # Ensure local ssh cache/trusted list is updated before we try to connect to the VMs.
            run_local(f"gcloud compute config-ssh --project {self.config['gcp_project']}")
        except Exception as exception:
            # if resources unavailable
            if "ZONE_RESOURCE_POOL_EXHAUSTED" in str(exception):
                # delete currently created resources
                self.obliterate(interactive=False)

                # update region-to-use
                valid_regions = self.config["gcp_regions"]
                self.config["region_index"] = (self.config["region_index"] + 1) % len(
                    valid_regions
                )
                self.config["region"] = valid_regions[self.config["region_index"]]

                # re-attempt creation
                self.create_all_vms()

            # in case of any other error, let the exception be thrown
            else:
                raise exception

    def list_vms(self, check_all_regions=False):
        additional_note = ""
        regions_to_check = [self.config["region"]]

        if check_all_regions:
            additional_note = "in all listed regions"
            regions_to_check = self.config["regions"]

        Log.debug(
            f"Getting list of VMs having names with prefix {self.config['prefix']}"
            f" {additional_note}"
        )
        all_vms_details = []

        for region in regions_to_check:
            for suffix in self.config["zones_suffixes"]:
                zone = f"{region}-{suffix}"
                vms = self.get_vms(zone, self.config["prefix"], True)
                if vms:
                    all_vms_details.extend(vms)

        return all_vms_details

    def extract_host_properties(self, virtual_machine, vm_name):
        properties = {"ip": virtual_machine["networkInterfaces"][0]["networkIP"]}
        if (
            "accessConfigs" in virtual_machine["networkInterfaces"][0]
            and "natIP" in virtual_machine["networkInterfaces"][0]["accessConfigs"][0]
        ):
            properties["public_ip"] = virtual_machine["networkInterfaces"][0]["accessConfigs"][0][
                "natIP"
            ]
        properties["name"] = vm_name
        properties["full_name"] = (
            f"{virtual_machine['name']}.{os.path.basename(virtual_machine['zone'])}"
            f".{self.config['gcp_project']}"
        )

        properties["cloud"] = self.cloud
        return properties

    def configure_lcm_vm(self):
        lcm_host = self.hosts_and_roles["hosts"][self.hosts_and_roles["roles"]["lcm"][0]]
        # Create lcm_user.
        self.create_lcm_user_if_needed(lcm_host)
        # Copy the public ssh-key.
        Log.info("Generating ssh key pair if needed.")
        run_local("test -f ~/.ssh/id_rsa.pub || ssh-keygen -f ~/.ssh/id_rsa -N ''")
        local_public_key = run_local("cat ~/.ssh/id_rsa.pub").stdout.strip()
        append_line_if_absent_sudo(
            lcm_host, f"/home/{self.user_name}/.ssh/authorized_keys", local_public_key
        )
        run_sudo_remote(
            lcm_host,
            (
                f"chown {self.user_name}:{self.user_name} "
                f"/home/{self.user_name}/.ssh/authorized_keys"
            ),
        )

        # Reopen connection as the lcm_user.
        # Temporarily changing the ssh config file to not use the gcloud identity file.
        try:
            run_local("sed -i 's/IdentityFile/#IdentityFile/' ~/.ssh/config")
            lcm_host["user"] = self.user_name
            open_new_connection(lcm_host)
        finally:
            run_local("sed -i 's/#IdentityFile/IdentityFile/' ~/.ssh/config")

        # Enable access for the other VMs.
        put_file(lcm_host, self.key_file, "/tmp/gcp_cloud_key")
        run_remote(lcm_host, "gcloud auth activate-service-account --key-file=/tmp/gcp_cloud_key")
        run_remote(lcm_host, "gcloud compute config-ssh")

    def delete_vm_instances(self, vms_to_delete):
        operations = []
        for virtual_machine in vms_to_delete:
            zone = os.path.basename(virtual_machine["zone"])
            operation = self._delete_vm(zone, virtual_machine["name"])
            if operation:
                operations.append(operation)

        Log.info("Waiting for GCP operations to complete ...")
        for operation in operations:
            self.wait_for_operation(operation)

    def _delete_vm(self, zone, vm_name):
        Log.info(f"Deleting vm {vm_name} in zone {zone} ...")
        return (
            self.compute.instances()  # pylint: disable=no-member
            .delete(project=self.config["gcp_project"], zone=zone, instance=vm_name)
            .execute()
        )

    def initialize_account(self):
        raise RuntimeError(f"Operation unsupported for cloud type {self.cloud}")
