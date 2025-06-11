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
import time

import boto3
from fabric import connection
from lib.common import (
    create_data_volume_init_command,
    create_logs_volume_init_command,
    run_local,
    run_remote,
)
from lib.constants import AWS_USER, PLACEHOLDER_BOOT_SCRIPT
from lib.log import Log
from lib.provisioner import Provisioner


class AwsProvisioner(Provisioner):
    """Provisioner implementation for AWS."""

    def __init__(
        self,
        operation,
        infra_config_file,
        infra_creds_file,
        is_multi_cloud: bool,
        hosts_file_name: str,
        gcp_creds: bool,
    ):
        super().__init__(
            "aws", operation, infra_config_file, infra_creds_file, is_multi_cloud, hosts_file_name
        )

        if gcp_creds:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = infra_creds_file

        # Verify that the creds file looks compatible.
        if self.key_file:
            self.verify_creds()

        self.config["regions"] = self.config["aws_regions"]
        self.config["region"] = self.config["regions"][self.config["region_index"]]
        self.config["vm_type"] = self.config["aws_vm_type"]
        self.config["vm_count"] = self.config["aws_vm_count"]

        self.ec2_client = boto3.client("ec2")
        self.ec2_resource = boto3.resource("ec2")
        self.subnet_count = 0

        self.user_name = AWS_USER

    @staticmethod
    def generate_bootscript(total_data_disks_count):
        data_volumes = []
        for disk_number in range(1, 1 + total_data_disks_count):
            data_volumes.append(f"/dev/nvme{disk_number+1}n1")
        boot_script = f"""#!/bin/bash
    echo Hello World!

    if test ! -f /mnt/disks/lcm_volumes_setup_done; then
        {create_logs_volume_init_command("/dev/nvme1n1", '/mnt/disks/disk1', "discard,defaults")}
        {create_data_volume_init_command(data_volumes, '/mnt/disks/data', "discard,defaults")}
        touch /mnt/disks/lcm_volumes_setup_done
    fi
        """
        return boot_script

    @staticmethod
    def get_disk_count(machine_description):
        disks = machine_description["InstanceStorageInfo"]["Disks"]
        count = 0

        for disk in disks:
            count += disk["Count"]

        return count

    def verify_creds(self):
        Log.debug(f"Doing basic validation of creds file {self.key_file}")
        with open(self.key_file, "r", encoding="UTF-8") as creds_file:
            first_line = creds_file.readline()
        expected = "BEGIN RSA PRIVATE KEY"
        if expected not in first_line:
            raise RuntimeError(
                f"AWS: expected 1st line of {self.key_file} to contain '{expected}'."
            )

    def connect_to_host(self, full_name):
        return connection.Connection(
            full_name, user=self.user_name, connect_kwargs={"key_filename": self.key_file}
        )

    def make_zone(self, suffix):
        return f"{self.config['region']}{suffix}"

    def set_up_vm_properties(self):
        for vm_role in Provisioner.VM_ROLES:
            extra_data_disks_count = 0
            if "extra_data_disks_count" in self.config["vm_type"][vm_role]:
                extra_data_disks_count = self.config["vm_type"][vm_role]["extra_data_disks_count"]

            total_data_disks_count = extra_data_disks_count

            if "machine_type" in self.config["vm_type"][vm_role]:
                machine_type = self.config["vm_type"][vm_role]["machine_type"]
                valid_types = self.ec2_client.describe_instance_types(InstanceTypes=[machine_type])
                machine_description = valid_types["InstanceTypes"][0]

                if not machine_description:
                    raise RuntimeError(
                        f"Machine Type requested for {vm_role},"
                        f" which is {machine_type}"
                        f" as per provided config file {self.infra_file},"
                        f" does not exist! Please retry with a valid config."
                    )

                if machine_description["InstanceStorageSupported"]:
                    total_data_disks_count += AwsProvisioner.get_disk_count(machine_description)

            if vm_role == "storage":
                self.config["vm_type"][vm_role]["startup_script"] = (
                    AwsProvisioner.generate_bootscript(total_data_disks_count)
                )
            else:
                self.config["vm_type"][vm_role]["startup_script"] = PLACEHOLDER_BOOT_SCRIPT

    def verify_setup(self):
        Log.info("Checking whether aws is initialized correctly.")
        try:
            run_local("aws configure get aws_access_key_id")
        except Exception as exception:
            raise RuntimeError(
                "aws is not configured properly. Run 'aws configure'."
            ) from exception

    def list_vms(self, check_all_regions=False):
        return self.get_vms(self.config["prefix"] + "-")

    def get_vms(self, vm_name, is_prefix=True):
        """
        This method gets all the VMs from AWS with the given name pattern.
        vm_name_filter can be of the form "example_name" or "example_name_prefix*".
        """
        out_vms = []
        Log.debug(f"Looking for VMs with names {vm_name} is_prefix {is_prefix}")
        result = self.ec2_client.describe_instances(
            Filters=[{"Name": "tag:Name", "Values": [f"{vm_name}*"]}]
        )

        for reservation in result["Reservations"]:
            vms = reservation["Instances"]
            for virtual_machine in vms:
                vm_name = ""
                for tag in virtual_machine["Tags"]:
                    if tag["Key"] == "Name":
                        vm_name = tag["Value"]
                Log.debug(f"{vm_name} : {virtual_machine['State']['Name']}")
                virtual_machine["name"] = vm_name
                virtual_machine["state"] = virtual_machine["State"]["Name"]
                if virtual_machine["state"] != "terminated":
                    out_vms.append(virtual_machine)

        return out_vms

    def create_vm_instances(self, vm_names, zones, vm_specs):
        created_instances = []
        for vm_name, zone in zip(vm_names, zones):
            # Check whether a VM with the same name already exists.
            vm_details = self.get_vms(vm_name, is_prefix=False)
            if vm_details:
                raise RuntimeError(f"A vm with name {vm_name} already exists!")

            # Populate instance config
            vm_config = {}
            vm_config["MinCount"] = 1
            vm_config["MaxCount"] = 1
            vm_config["Placement"] = {"AvailabilityZone": zone}
            vm_config["TagSpecifications"] = [
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": vm_name}]}
            ]
            vm_config["KeyName"] = self.config["aws_key_name"]
            vm_config["ImageId"] = self.config["aws_image_id"]
            vm_config["InstanceType"] = vm_specs["machine_type"]
            vm_config["UserData"] = vm_specs["startup_script"]

            zone_id = zone[-1]
            if vm_specs["exposure"] == "internal" and not self.is_multi_cloud:
                vm_config["SecurityGroupIds"] = self.config["aws_internal_security_groups"]
                vm_config["SubnetId"] = self.config["aws_zone_subnets"]["private"][zone_id]
            else:
                vm_config["SubnetId"] = self.config["aws_zone_subnets"]["public"][zone_id]

                if vm_specs["exposure"] == "external":
                    vm_config["SecurityGroupIds"] = self.config["aws_external_security_groups"]
                else:
                    vm_config["SecurityGroupIds"] = self.config["aws_lb_security_groups"]

            disks = []
            disks.append(
                {
                    "DeviceName": "/dev/sda1",
                    "VirtualName": "boot-disk",
                    "Ebs": {"VolumeSize": vm_specs["os_disk_size_gb"], "VolumeType": "gp3"},
                }
            )

            log_disk_size_gb = vm_specs["log_disk_size_gb"]
            if log_disk_size_gb > 0:
                disks.append(
                    {
                        "DeviceName": "/dev/sdb",
                        "VirtualName": "boot-disk",
                        "Ebs": {"VolumeSize": log_disk_size_gb, "VolumeType": "gp3"},
                    }
                )

            additional_notes = (
                f"of type {vm_specs['machine_type']}, "
                f"with boot disk size {vm_specs['os_disk_size_gb']}, "
                f"log disk size {log_disk_size_gb}"
            )

            # The extra disks, if present.
            if "extra_data_disks_count" in vm_specs:
                extra_data_disks_count = vm_specs["extra_data_disks_count"]
                extra_disk_size_gb = vm_specs["extra_disk_size_gb"]
                additional_notes += f""", and {extra_data_disks_count} additional disks of size
                {extra_disk_size_gb} gb"""

                for disk_num in range(extra_data_disks_count):
                    disks.append(
                        {
                            "DeviceName": f'/dev/sd{chr(ord("c")+disk_num)}',
                            "VirtualName": f"extra-disk-{disk_num+1}",
                            "Ebs": {"VolumeSize": extra_disk_size_gb, "VolumeType": "gp3"},
                        }
                    )
            else:
                additional_notes += "."

            vm_config["BlockDeviceMappings"] = disks

            Log.info(f"Creating vm with name {vm_name} in zone {zone}, {additional_notes}")

            instance_info = self.ec2_client.run_instances(**vm_config)
            created_instances.append(instance_info["Instances"][0]["InstanceId"])

        return created_instances

    def confirm_instance_creations(self, provisioned_instances):
        """Waits for specified instances being created"""
        Log.info("Waiting for AWS operations to complete ...")
        time.sleep(5)
        instances = self.ec2_resource.instances.filter(InstanceIds=provisioned_instances)

        for instance in instances:
            instance.wait_until_running()
        time.sleep(5)

    def extract_host_properties(self, virtual_machine, vm_name):
        properties = {}
        properties = {"ip": virtual_machine["NetworkInterfaces"][0]["PrivateIpAddress"]}
        if (
            "Association" in virtual_machine["NetworkInterfaces"][0]
            and "PublicIp" in virtual_machine["NetworkInterfaces"][0]["Association"]
        ):
            properties["public_ip"] = virtual_machine["NetworkInterfaces"][0]["Association"][
                "PublicIp"
            ]

        properties["name"] = vm_name

        if (
            "Association" in virtual_machine["NetworkInterfaces"][0]
            and "PublicDnsName" in virtual_machine["NetworkInterfaces"][0]["Association"]
        ):
            properties["full_name"] = virtual_machine["NetworkInterfaces"][0]["Association"][
                "PublicDnsName"
            ]
        else:
            properties["full_name"] = vm_name

        properties["cloud"] = self.cloud
        return properties

    def configure_lcm_vm(self):
        lcm_host = self.hosts_and_roles["hosts"][self.hosts_and_roles["roles"]["lcm"][0]]
        with open(self.key_file, "r", encoding="UTF-8") as key_file:
            key = key_file.read().strip()
        run_remote(lcm_host, "sudo rm -rf ~/.ssh/id_rsa")
        run_remote(lcm_host, f'echo "{key}" | tee ~/.ssh/id_rsa')
        run_remote(lcm_host, "chmod 600 ~/.ssh/id_rsa")
        run_remote(lcm_host, "ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub")

    def delete_vm_instances(self, vms_to_delete):
        instance_ids = []
        for virtual_machine in vms_to_delete:
            instance_ids.append(virtual_machine["InstanceId"])
        self.ec2_resource.instances.filter(InstanceIds=instance_ids).terminate()

        Log.info("Waiting for AWS operations to complete ...")
        waiter = self.ec2_client.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=instance_ids)

    def create_vpc(self):
        vpc_name = self.config["aws_vpc_name"]
        response = self.ec2_client.create_vpc(
            CidrBlock=self.config["aws_vpc_cidr_block"],
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": vpc_name}],
                }
            ],
        )

        # Get VPC ID and wait for creation confirmation
        vpc_id = response["Vpc"]["VpcId"]
        self.ec2_client.get_waiter("vpc_available").wait(VpcIds=[vpc_id])

        # Enable dns name resolution.
        self.ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

        Log.info(f"VPC {vpc_name} created with ID {vpc_id}")
        return vpc_id

    def create_igw(self, vpc_id):
        """Creates a new internet gateway and attach it to the VPC"""
        igw_name = self.config["aws_igw_name"]
        response = self.ec2_client.create_internet_gateway(
            TagSpecifications=[
                {
                    "ResourceType": "internet-gateway",
                    "Tags": [{"Key": "Name", "Value": igw_name}],
                }
            ],
        )

        # Get IGW ID and wait for creation confirmation
        igw_id = response["InternetGateway"]["InternetGatewayId"]
        self.ec2_client.get_waiter("internet_gateway_exists").wait(InternetGatewayIds=[igw_id])

        # Attach the internet gateway to VPC
        self.ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

        Log.info(f"Internet Gateway {igw_name} created with ID {igw_id}")
        return igw_id

    def create_route_table(self, vpc_id, name):
        response = self.ec2_client.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    "ResourceType": "route-table",
                    "Tags": [{"Key": "Name", "Value": name}],
                }
            ],
        )

        # Get Route Table ID
        route_table_id = response["RouteTable"]["RouteTableId"]

        Log.info(f"Route table {name} created with ID {route_table_id}")
        return route_table_id

    def get_next_subnet_cidr_block(self):
        vpc_cidr = self.config["aws_vpc_cidr_block"]

        # We add 8 to move to the next octet of the IP address.
        subnet_mask = int(vpc_cidr.split("/")[-1]) + 8
        subnet = vpc_cidr.split("/")[0].split(".")
        self.subnet_count += 1

        if subnet_mask == 16:
            return f"{subnet[0]}.{self.subnet_count}.0.0/16"
        if subnet_mask == 24:
            return f"{subnet[0]}.{subnet[1]}.{self.subnet_count}.0/24"

        return ""

    def create_subnets(self, vpc_id, subnet_prefix):
        """Creates subnets for zones specified by property 'zones_suffixes' in infra config."""
        subnet_ids = []
        for zone_suffix in self.config["zones_suffixes"]:
            zone = self.make_zone(zone_suffix)
            subnet_cidr_block = self.get_next_subnet_cidr_block()
            subnet_name = f"{subnet_prefix}-{zone}"
            response = self.ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=subnet_cidr_block,
                AvailabilityZone=zone,
                TagSpecifications=[
                    {
                        "ResourceType": "subnet",
                        "Tags": [{"Key": "Name", "Value": subnet_name}],
                    }
                ],
            )
            subnet_id = response["Subnet"]["SubnetId"]
            subnet_ids.append(subnet_id)
            Log.info(
                f"Subnet {subnet_name} created with ID {subnet_id}, "
                f"in zone {zone} with CIDR block {subnet_cidr_block}"
            )

        # Wait for creation confirmation
        self.ec2_client.get_waiter("subnet_available").wait(SubnetIds=subnet_ids)

        return subnet_ids

    def configure_network(self, vpc_id, igw_id):
        """Creates and configures public and private route tables and subnets, elastic IP if
        necessary, and NAT gateway."""
        # Create public route table
        public_route_table_name = f"{self.config['aws_route_table_prefix']}-public"
        public_route_table_id = self.create_route_table(vpc_id, public_route_table_name)
        self.ec2_client.create_route(
            RouteTableId=public_route_table_id, GatewayId=igw_id, DestinationCidrBlock="0.0.0.0/0"
        )

        # Create public subnets
        public_subnet_ids = self.create_subnets(vpc_id, self.config["aws_public_subnet_prefix"])
        for public_subnet in public_subnet_ids:
            self.ec2_client.associate_route_table(
                SubnetId=public_subnet, RouteTableId=public_route_table_id
            )
            self.ec2_client.modify_subnet_attribute(
                SubnetId=public_subnet, MapPublicIpOnLaunch={"Value": True}
            )

        Log.info("Public subnets configured successfully")

        # Create private route table
        private_route_table_name = f"{self.config['aws_route_table_prefix']}-private"
        private_route_table_id = self.create_route_table(vpc_id, private_route_table_name)

        # Create private subnets
        private_subnet_ids = self.create_subnets(vpc_id, self.config["aws_private_subnet_prefix"])
        for private_subnet in private_subnet_ids:
            self.ec2_client.associate_route_table(
                SubnetId=private_subnet, RouteTableId=private_route_table_id
            )

        Log.info("Private subnets configured successfully")

        # Create Elastic IP if not provided
        elastic_ip_allocation_id = self.config.get("aws_elastic_ip_allocation_id")
        if not elastic_ip_allocation_id:
            response = self.ec2_client.allocate_address(
                Domain="vpc",
                TagSpecifications=[
                    {
                        "ResourceType": "elastic-ip",
                        "Tags": [{"Key": "Name", "Value": "bios-elastic-ip"}],
                    }
                ],
            )
            elastic_ip_allocation_id = response["AllocationId"]
            Log.info(f"Created new Elastic IP {response['PublicIp']} as none provided")

        lcm_subnet = public_subnet_ids[0]
        response = self.ec2_client.create_nat_gateway(
            SubnetId=lcm_subnet,
            AllocationId=elastic_ip_allocation_id,
            ClientToken=f"NAT for public subnet {lcm_subnet}",
        )

        # Wait for creation confirmation
        nat_gateway_id = response["NatGateway"]["NatGatewayId"]
        self.ec2_client.get_waiter("nat_gateway_available").wait(NatGatewayIds=[nat_gateway_id])
        Log.info(f"NAT Gateway created with ID {nat_gateway_id}")

        self.ec2_client.create_route(
            RouteTableId=private_route_table_id,
            NatGatewayId=nat_gateway_id,
            DestinationCidrBlock="0.0.0.0/0",
        )
        Log.info("NAT Gateway configured successfully")

    def create_key_pair_file(self):
        """Create a key pair file locally to be used for remote access among service instances"""
        key_name = self.config["aws_key_name"]
        key_pair_file_name = key_name + ".pem"
        if os.path.exists(key_pair_file_name):
            Log.info(f"Key pair file {key_pair_file_name} already exists, skipping creation")
            return
        response = self.ec2_client.create_key_pair(KeyName=key_name)
        private_key = response["KeyMaterial"]
        with open(key_pair_file_name, "w+", encoding="UTF-8") as key_file:
            key_file.write(private_key)
        Log.info(f"Key Pair {key_name} generated, the file was saved to {key_pair_file_name}")

    def create_security_group(self, vpc_id, sg_name, sg_description):
        response = self.ec2_client.create_security_group(
            GroupName=sg_name,
            VpcId=vpc_id,
            Description=sg_description,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": "Name", "Value": sg_name}],
                }
            ],
        )

        # Wait for creation confirmation
        sg_id = response["GroupId"]
        self.ec2_client.get_waiter("security_group_exists").wait(GroupIds=[sg_id])

        Log.info(f"Security Group {sg_name} created with ID {sg_id}")
        return sg_id

    def configure_security_groups(self, vpc_id):
        # Create public security group
        public_security_group_name = f"{self.config['aws_security_group_prefix']}-public"
        public_security_group_id = self.create_security_group(
            vpc_id, public_security_group_name, "Public Security Group"
        )

        # Configure public security group
        self.ec2_client.authorize_security_group_ingress(
            GroupId=public_security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": self.config["aws_vpc_cidr_block"]}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )

        Log.info("Public security group {public_security_group_name} created and configured")

        # Create private security group
        private_security_group_name = f"{self.config['aws_security_group_prefix']}-private"
        private_security_group_id = self.create_security_group(
            vpc_id, private_security_group_name, "Private Security Group"
        )

        # Configure private security group
        self.ec2_client.authorize_security_group_ingress(
            GroupId=private_security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 0,
                    "ToPort": 65535,
                    "IpRanges": [{"CidrIp": self.config["aws_vpc_cidr_block"]}],
                },
            ],
        )

        Log.info("Private security group {private_security_group_name} created and configured")

        # Create load-balancer security group
        lb_security_group_name = f"{self.config['aws_security_group_prefix']}-lb"
        load_balancer_security_group_id = self.create_security_group(
            vpc_id, lb_security_group_name, "Load Balancer Security Group"
        )

        # Configure load_balancer security group
        self.ec2_client.authorize_security_group_ingress(
            GroupId=load_balancer_security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": self.config["aws_vpc_cidr_block"]}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )

        Log.info("Load balancer security group {lb_security_group_name} created and configured")

    def initialize_account(self):
        vpc_id = self.create_vpc()
        igw_id = self.create_igw(vpc_id)
        self.configure_network(vpc_id, igw_id)
        self.create_key_pair_file()
        self.configure_security_groups(vpc_id)
        Log.info("Done initializing the AWS account")
