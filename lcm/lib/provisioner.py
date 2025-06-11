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
import time
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, Dict, List

import yaml
from lib.common import (
    append_line_if_absent_sudo,
    deep_add_dictionaries,
    deep_merge_dictionaries,
    get_effective_config,
    get_lcm_path,
    get_name_and_ip,
    open_new_connection,
    run_local,
    run_remote,
    run_sudo_remote,
    validate_vm_counts,
)
from lib.constants import DEFAULT_INFRA_CONFIG_PATH
from lib.log import Log


class Provisioner(ABC):
    """Provisioner base class."""

    CLOUD_TYPES = ["aws", "gcp"]
    VM_ROLES = ["lcm", "lb", "compute", "storage"]

    def __init__(
        self,
        cloud,
        operation,
        infra_config_file,
        infra_creds_file,
        is_multi_cloud: bool,
        hosts_file_name: str,
    ):
        self.cloud = cloud
        self.operation = operation
        self.infra_file = infra_config_file
        self.is_multi_cloud = is_multi_cloud
        self.hosts_file_name = hosts_file_name
        if operation == "update_dns_records" and not self.hosts_file_name:
            raise RuntimeError(
                "hosts file name must be specified when operation is update_dns_record"
            )

        if infra_creds_file:
            self.key_file = os.path.abspath(infra_creds_file)
        else:
            self.key_file = infra_creds_file

        # Initialize values from config.
        default_infra_config_file = get_lcm_path()
        default_infra_config_file += DEFAULT_INFRA_CONFIG_PATH

        self.config = get_effective_config(infra_config_file, default_infra_config_file)
        self.config["prefix"] = self.config["cluster_dns_name"].split(".")[0]
        self.config["region_index"] = 0

        self.user_name = ""

        self.roles = {}
        self.hosts_and_roles = {}

        self.is_lcm_cloud = False
        self.is_interactive = False

    # abstract methods (i.e., cloud specific parts) ##############################

    @abstractmethod
    def connect_to_host(self, full_name):
        """Connects to a host"""

    @abstractmethod
    def make_zone(self, suffix):
        """Makes zone name"""

    @abstractmethod
    def verify_setup(self):
        """Verifies the cloud interface is initialized correctly"""

    @abstractmethod
    def set_up_vm_properties(self):
        """Sets up VM instance parameters"""

    @abstractmethod
    def create_vm_instances(self, vm_names, zones, vm_specs):
        """Creates VM instances"""

    @abstractmethod
    def confirm_instance_creations(self, provisioned_instances):
        """Waits and verifies VM instance creations"""

    @abstractmethod
    def extract_host_properties(self, virtual_machine: dict, vm_name: str) -> Dict[str, Any]:
        """Extracts host properties"""

    @abstractmethod
    def list_vms(self, check_all_regions=False) -> List[dict]:
        """Lists VM instances"""

    @abstractmethod
    def configure_lcm_vm(self):
        """Configures LCM instance"""

    @abstractmethod
    def delete_vm_instances(self, vms_to_delete):
        """Deletes VM instances"""

    @abstractmethod
    def initialize_account(self):
        """Initializes cloud account."""

    # common methods #############################################################

    def set_interactive(self, is_interactive: bool) -> "Provisioner":
        """Sets interactive mode flag and returns self"""
        self.is_interactive = is_interactive
        return self

    def execute(self):
        """Executes the operation configured for the instance."""
        operator = {
            "list": self.list,
            "provision": self.provision,
            "obliterate": self.obliterate,
            "demolish": self.obliterate,
            "update_dns_records": self.update_dns_records,
            "initialize_account": self.initialize_account,
        }[self.operation]

        operator()

    def create_all_vms(self):
        """Creates VM images specified in the infra config file."""
        provision_objects = []

        for vm_role in Provisioner.VM_ROLES:
            Log.info(f"Creating VMs of type {vm_role}")
            vm_specs = self.config["vm_type"][vm_role].copy()
            vm_specs["role"] = vm_role

            names = []
            zones = []
            suffices = self.config["zones_suffixes"]
            suffix_count = len(suffices)

            vm_count = self.config["vm_count"][vm_role]
            vm_done = 0
            if "vm_done" in self.config:
                vm_done = self.config["vm_done"][vm_role]

            if vm_role == "lcm" and vm_count:
                self.is_lcm_cloud = True
                names.append(f"{self.config['prefix']}-lcm")
                self.roles[vm_role] = ["lcm"]
                zones.append(self.make_zone(suffices[0]))

            else:
                vm_count = self.config["vm_count"][vm_role]
                self.roles[vm_role] = []
                for vm_number in range(1 + vm_done, 1 + vm_done + vm_count):
                    index = vm_number - 1
                    if vm_role == "lb":
                        vm_name_core = f"lb-{vm_number}"
                    elif vm_role == "compute":
                        vm_name_core = f"compute-{vm_number}"
                    else:  # vm_type_string == "storage":
                        sub_role = self.config["storage_sub_roles"][index % 3]
                        sub_role_vm_number = (index // 3) + 1
                        vm_name_core = f"{sub_role}-{sub_role_vm_number}"

                    names.append(f"{self.config['prefix']}-{vm_name_core}")
                    zones.append(self.make_zone(suffices[index % suffix_count]))
                    self.roles[vm_role].append(vm_name_core)

            creation_objects = self.create_vm_instances(names, zones, vm_specs)

            if creation_objects:
                provision_objects += creation_objects

        self.confirm_instance_creations(provision_objects)
        Log.info("VM instances created successfully")

    def make_hosts_file_contents(self):
        """Make hosts.yaml file contents that are kept as property 'hosts_and_roles'.
        The contents are save to a hosts.yaml file later when necessary.
        This method also tests SSH connectivity to LCM.
        """
        host_entries = {}
        lcm_host_full_name = ""
        all_vms = self.list_vms()
        for virtual_machine in all_vms:
            vm_name_core = virtual_machine["name"][len(self.config["prefix"]) + 1 :]
            host = self.extract_host_properties(virtual_machine, vm_name_core)
            host_full_name = host["full_name"]
            if vm_name_core == "lcm":
                lcm_host_full_name = host_full_name
                self.create_lcm_connection(host)

            host_entries[vm_name_core] = host

        # TODO(Naoki): Move this to the subclass
        if self.cloud == "aws":
            run_local("touch ~/.ssh/config")
            run_local("cp ~/.ssh/config ~/.ssh/config.backup")
            run_local(
                f"""echo 'HOST {lcm_host_full_name}
    USER {self.user_name}
    IdentityFile {self.key_file}' | tee -a ~/.ssh/config > /dev/null"""
            )

        hosts_and_roles = {}
        hosts_and_roles["hosts"] = host_entries
        # Use compute nodes if load is not set up explicitly
        if not self.roles.get("load"):
            self.roles["load"] = self.roles["compute"].copy()
        self.roles["jupyter_hub"] = self.roles["compute"][:1].copy()

        hosts_and_roles["roles"] = self.roles
        self.hosts_and_roles = hosts_and_roles

    def configure_internal_vms(self):
        lcm_host = self.hosts_and_roles["hosts"][self.hosts_and_roles["roles"]["lcm"][0]]

        # If a key pair for ssh does not exist on the LCM machine yet, generate it.
        Log.info("Generating ssh key pair if needed.")
        run_remote(lcm_host, "test -f ~/.ssh/id_rsa.pub || ssh-keygen -f ~/.ssh/id_rsa -N ''")
        lcm_public_key = run_remote(lcm_host, "cat ~/.ssh/id_rsa.pub").stdout.strip()

        # Set up connections to all hosts.
        for name, entry in self.hosts_and_roles["hosts"].items():
            if entry == lcm_host or entry["cloud"] != "gcp":
                continue
            Log.debug(f"Opening connection to host {name} ({entry['ip']})")
            open_new_connection(entry, gateway=lcm_host["connection"])
            self.create_lcm_user_if_needed(entry)
            append_line_if_absent_sudo(
                entry, f"/home/{self.user_name}/.ssh/authorized_keys", lcm_public_key
            )
            run_sudo_remote(
                entry,
                (
                    f"chown {self.user_name}:{self.user_name} "
                    f"/home/{self.user_name}/.ssh/authorized_keys"
                ),
            )

    def write_hosts_file(self):
        hosts_and_roles_concise = {}

        if not self.is_multi_cloud:
            hosts_and_roles_concise["cloud"] = self.cloud
            hosts_and_roles_concise["region"] = self.config["region"]

        hosts_and_roles_concise["roles"] = self.hosts_and_roles["roles"]
        hosts_concise = {}
        hosts_and_roles_concise["hosts"] = hosts_concise
        for name, host in self.hosts_and_roles["hosts"].items():
            hosts_concise[name] = {}

            if host["cloud"] == "gcp":
                hosts_concise[name]["full_name"] = host["full_name"]

            hosts_concise[name]["user"] = self.user_name

            if self.is_multi_cloud:
                hosts_concise[name]["ip"] = host["public_ip"]
                hosts_concise[name]["cloud"] = host["cloud"]
            else:
                hosts_concise[name]["ip"] = host["ip"]

        for name in self.hosts_and_roles["roles"]["lb"]:
            hosts_concise[name]["public_ip"] = self.hosts_and_roles["hosts"][name]["public_ip"]

        local_lcm_dir = os.environ["HOME"] + "/lcm"
        os.system(f"mkdir -p {local_lcm_dir}")
        with open(local_lcm_dir + "/hosts.yaml", "w", encoding="UTF-8") as outfile:
            yaml.dump(hosts_and_roles_concise, outfile)
        with open(local_lcm_dir + "/hosts_verbose.yaml", "w", encoding="UTF-8") as outfile:
            print(repr(self.hosts_and_roles), file=outfile)
        run_local(f"mkdir -p {local_lcm_dir}/{self.config['cluster_dns_name']}")
        run_local(f"cp {local_lcm_dir}/*.yaml {local_lcm_dir}/{self.config['cluster_dns_name']}/")

    def initialize_lcm_vm(self):
        lcm_host = self.hosts_and_roles["hosts"][self.hosts_and_roles["roles"]["lcm"][0]]
        lcm_host_full_name = lcm_host["full_name"]

        Log.info("Copying LCM code to LCM VM")
        lcm_dir = os.environ["HOME"] + "/lcm"
        os.system(f"mkdir -p {lcm_dir}")

        # If a local config file is present copy it, otherwise copy the example file.
        cluster_config_to_add = ""
        try:
            with open(
                f"{get_lcm_path()}/local_configs/cluster_config.yaml", "r", encoding="UTF-8"
            ) as conf_file:
                cluster_config_to_add = conf_file.read()
        except FileNotFoundError as _:
            with open(
                f"{get_lcm_path()}/example_configs/cluster_config.yaml", "r", encoding="UTF-8"
            ) as conf_file:
                cluster_config_to_add = conf_file.read()

        with open(f"{lcm_dir}/cluster_config.yaml", "w", encoding="UTF-8") as cluster_config_file:
            cluster_config_file.write(f"cluster_dns_name: {self.config['cluster_dns_name']}\n")
            cluster_config_file.write(cluster_config_to_add)

        # Copy certificate files that will get picked up by the push_lcm_to_vm script.
        run_local(f"cp {lcm_dir}/{self.config['cluster_dns_name']}/*.pem {lcm_dir}/", [1])
        run_local(f"{get_lcm_path()}/push_lcm_to_vm.sh {lcm_host_full_name} {self.user_name}")

        Log.info("Initializing LCM on LCM VM")
        init_lcm_cmd = "source /isima/lcm/lcm/initialize_lcm.sh --download-lcm false"
        if self.config["bios_python_sdk_version"] != "latest":
            init_lcm_cmd += f" --bios-python-sdk-version {self.config['bios_python_sdk_version']}"
        run_remote(lcm_host, init_lcm_cmd)

    def get_next_steps_message(self):
        lcm_host = self.hosts_and_roles["hosts"][self.hosts_and_roles["roles"]["lcm"][0]]
        lcm_host_full_name = lcm_host["full_name"]
        lb_vms_public_ips = []
        for name in self.hosts_and_roles["roles"]["lb"]:
            lb_vms_public_ips.append(self.hosts_and_roles["hosts"][name]["public_ip"])
        lb_vms_public_ips_str = ", ".join(lb_vms_public_ips)
        next_steps_message = f"""
    Next steps:
        * On LCM VM ({lcm_host_full_name}) update
          /isima/lcm/env/cluster_config.yaml if needed.
        * Create SSL certificate and copy file to /isima/lcm/env/ if not already done above.

        * Update DNS record(s) for the cluster DNS name to point to [{lb_vms_public_ips_str}]:
          Use the sub-command update_dns_records as:
                ./provision.py gcp update_dns_records {self.infra_file} ./gcp_infra_creds.json $HOME/lcm/hosts.yaml

        * Ensure firewall is updated to allow https (TCP port 443) access to the above IPs.

        * Log in to the LCM VM and run everything else below in that VM:
                ssh -o StrictHostKeyChecking=no {lcm_host_full_name}
        """
        if self.cloud == "gcp":
            next_steps_message += f"""
                sudo su - {self.user_name}
            """
        next_steps_message += """

        * Install bi(OS) cluster:
                source /isima/lcm/lcm_venv/bin/activate
                /isima/lcm/lcm/install_bios.py install
            Alternatively (for safety against lost connection):
                nohup /isima/lcm/lcm/install_bios.py install & tail -F $HOME/nohup.out

            Optionally, you can monitor verbose logs:
                tail -F /isima/lcm/log/trace_compact__all_hosts.log

        * Create a tenant:
                source /isima/lcm/lcm_venv/bin/activate
                /isima/lcm/lcm/create_tenant.py /isima/lcm/env/tenant.yaml
        """
        return next_steps_message

    def update_dns_record(self, url, ips):
        dns_managed_zone = self.config["dns_managed_zone"]
        run_local(f"gcloud dns record-sets delete {url} --type=A --zone={dns_managed_zone}", [1])
        run_local(
            f"gcloud dns record-sets create {url} --rrdatas={ips}"
            f" --ttl=60 --type=A --zone={dns_managed_zone}"
        )

    def validate_vm_counts(self):
        roles = {}
        if self.is_multi_cloud:
            for cloud in Provisioner.CLOUD_TYPES:
                roles += Counter(self.config[f"{cloud}_vm_count"])
        else:
            roles = self.config[f"{self.cloud}_vm_count"]

        validate_vm_counts(roles)

    def create_lcm_connection(self, host):
        full_name = host["full_name"]
        Log.debug(f"Opening connection to host {full_name}")
        done = False
        waited = 0
        while not done:
            try:
                host["connection"] = self.connect_to_host(full_name)
                host["connection"].open()
                Log.debug(f"Successfully opened connection to host {full_name}")
                done = True
            except Exception as exception:
                if waited >= self.config["vm_boot_wait_time_secs"]:
                    raise RuntimeError(
                        f"Could not ssh to {get_name_and_ip(host)}"
                        f" after waiting {waited} seconds."
                    ) from exception
                Log.debug(f"Waiting for {get_name_and_ip(host)} to boot up ...")
                host["connection"].close()
                time.sleep(10)
                waited += 10

        # wait for VM to initialize
        time.sleep(5)

    def create_lcm_user_if_needed(self, host):
        Log.info(
            f"Creating user {self.user_name} if it does not already exist on "
            f"{get_name_and_ip(host)}"
        )
        try:
            run_remote(host, f"id {self.user_name}")
            Log.debug(
                f"On host {get_name_and_ip(host)}: user {self.user_name} is already present."
            )
        except Exception:
            Log.debug(f"On host {get_name_and_ip(host)}: creating {self.user_name} user.")
            run_remote(host, f"sudo adduser --disabled-password --gecos '' {self.user_name}")
        run_remote(host, f"sudo usermod -aG sudo {self.user_name}")
        run_remote(host, "echo '%sudo   ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo")
        run_remote(host, f"sudo mkdir -p /home/{self.user_name}/.ssh")
        run_remote(
            host, f"sudo chown -R {self.user_name}:{self.user_name} /home/{self.user_name}/.ssh"
        )

    def list(self):
        Log.info(f"Listing all resources provisioned with prefix '{self.config['prefix']}-'.")

        all_vms = self.list_vms(check_all_regions=True)
        if not all_vms:
            Log.info("Did not find any VMs")
            return

        vm_names = f"Found {len(all_vms)} VMs:"
        for virtual_machine in all_vms:
            vm_names += "\n                             " + virtual_machine["name"]
            if self.cloud == "aws":
                vm_names += f" : {virtual_machine['state']}"

        Log.info(vm_names)

    def obliterate(self, interactive=None):
        """Demolishes VM instances"""
        Log.info(
            f"Completely terminating and deleting all resources provisioned with"
            f" prefix '{self.config['prefix']}-'."
        )
        all_vms = self.list_vms(check_all_regions=True)
        if not all_vms:
            Log.info("Did not find any VMs to delete.")
            return

        vm_names = f"Deleting these {len(all_vms)} VMs:"
        for virtual_machine in all_vms:
            vm_names += "\n                             " + virtual_machine["name"]
        Log.info(vm_names)

        if interactive if interactive is not None else self.is_interactive:
            resp = input("Do you want to continue? (yes/no)? ")
            if resp != "yes":
                Log.info("The nodes won't be deleted.\n Quitting.")
                sys.exit()

        self.delete_vm_instances(all_vms)
        Log.marker(f"Completed deleting infrastructure with prefix '{self.config['prefix']}-'!")

    def provision_core(self):
        Log.info(f"Provisioning infrastructure with prefix '{self.config['prefix']}-'.")
        self.verify_setup()
        self.set_up_vm_properties()
        self.create_all_vms()
        self.make_hosts_file_contents()
        self.configure_lcm_vm()

    def provision(self, other_hosts=None):
        self.provision_core()

        if other_hosts:
            deep_merge_dictionaries(self.hosts_and_roles["hosts"], other_hosts["hosts"])
            deep_add_dictionaries(self.hosts_and_roles["roles"], other_hosts["roles"])
            Log.debug(f"Merged HnR: {self.hosts_and_roles}")

        self.write_hosts_file()
        self.configure_internal_vms()
        self.initialize_lcm_vm()
        next_steps_message = self.get_next_steps_message()
        Log.marker(
            f"Completed provisioning infrastructure with prefix '{self.config['prefix']}-'!"
            f"\n\n{next_steps_message}"
        )

    def update_dns_records(self):
        hosts_filename = self.hosts_file_name
        url = self.config["cluster_dns_name"]
        hosts_and_roles_concise = None
        with open(hosts_filename, "r", encoding="UTF-8") as hosts_file:
            try:
                hosts_and_roles_concise = yaml.safe_load(hosts_file)
            except yaml.YAMLError as exception:
                raise RuntimeError(
                    "Error parsing hosts.yaml. Enter correct values and try again."
                ) from exception

        Log.info(f"Updating DNS record for the url {url}")
        lb_vms_public_ips = []
        for name in hosts_and_roles_concise["roles"]["lb"]:
            if "public_ip" in hosts_and_roles_concise["hosts"][name]:
                lb_vms_public_ips.append(hosts_and_roles_concise["hosts"][name]["public_ip"])
            else:
                lb_vms_public_ips.append(hosts_and_roles_concise["hosts"][name]["ip"])
        lb_vms_public_ips_str = ",".join(lb_vms_public_ips)
        dns_project = self.config["dns_project"]
        run_local(f"gcloud config set project {dns_project}")
        run_local("gcloud services enable dns.googleapis.com")

        sql_url_1 = f"system-sql.{url}"
        sql_url_2 = f"tenant1-sql.{url}"
        self.update_dns_record(url, lb_vms_public_ips_str)
        self.update_dns_record(sql_url_1, lb_vms_public_ips_str)
        self.update_dns_record(sql_url_2, lb_vms_public_ips_str)

        if self.cloud == "gcp":
            run_local(f"gcloud config set project {self.config['gcp_project']}")

        Log.info(
            f"DNS record for urls {url}, {sql_url_1}, {sql_url_2} updated to "
            f"{lb_vms_public_ips_str}"
        )
