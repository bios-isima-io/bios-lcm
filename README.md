# LCM - bi(OS) Life Cycle Manager

LCM can be used to:

1. Provision infrastructure (including VMs and storage) in a cloud such as GCP.
1. Install a bi(OS) cluster on a given set of hosts (either provisioned using LCM or created separately).
2. Upgrade bi(OS) components.

See [Provisioner User Guide](PROVISIONER.md) and
[Manual Provisioning Guide](MANUAL_PROVISIONING_GUIDE.md) for provisioning. 
This document describes how to install and upgrade bi(OS) by using LCM.

## Getting Started
### Prerequisites

In order to install a bi(OS) service cluster, you need

- A set of Ubuntu 22.04 hosts running in x86_64 architectures
- A IP-resolvable domain name
- A valid server certificate for the domain name

See See [Provisioner User Guide](PROVISIONER.md) and [Manual Provisioning Guide](MANUAL_PROVISIONING_GUIDE.md) to prepare for the service hosts.

### Building LCM

Run the `build.sh` script:

```
./build.sh
```

The built image is `target/bios-lcm.tar.gz`.  The image can be used for installing LCM
as well as upgrading.

### Steps to Install bi(OS)

1. Install LCM to the lcm host by
   - The service cluster must have an LCM host. We will install the LCM there.
   - Copy the installation image:
     ```
     scp target/bios-lcm.tar.gz <lcm_hostname>:
     ```
   - Sign in to the lcm host and run the following steps:
     ```
     tar xf ${HOME}/bios-lcm.tar.gz
     bios-lcm/install_lcm.sh
     source /isima/lcm/lcm_venv/bin/activate
     ```
1. Copy the server certificates to lcm:<br>
   ```
   scp server.cert.pem server.key.pem <lcm_hostname>:/isima/lcm/env/
   ```
1. Edit `/isima/lcm/env/hosts.yaml` and `/isima/lcm/env/cluster_config.yaml` on the lcm host
1. Copy biOS images files to directory `/isima/lcm/images`
1. Run the LCM installer:
   ```
   /isima/lcm/lcm/install_bios.py install
   ```

### Detail Steps to Install bi(OS)

#### Host Requirements

bi(OS) cluster needs multiple hosts to run a distributed data platform. One of the machines is used to run the bi(OS) Life Cycle Manager (LCM). You can use the LCM host to install the cluster and administer it.

When provisioning the VMs for running bi(OS) please ensure that the following requirements are met:

1. All hosts should run Ubuntu 22.04 LTS.
1. It should be possible to ssh from the LCM VM to all hosts (including itself)
    using their IP address, e.g. `ssh <ip address>` should succeed.
1. All storage hosts must have a volume for logs, unmounted or mounted at /mnt/disks/disk1.
   Ideally it should be a dedicated SSD.
1. All storage hosts must have one or more volumes for data, unmounted or at paths with the same
    prefix, followed by numbers starting from 1, e.g. /mnt/disks/data1, /mnt/disks/data2, etc.
    It is OK for different hosts to have different number of data directories.
    Ideally they should be separate NVMe disks.

#### Build LCM

Run the build script at the top of the LCM repository.

```
./build.sh
```

The LCM package is created at `target/bios-lcm.tar.gz`. This package can be used for installing
or upgrading LCM.

#### Install LCM

Send the LCM package bios-lcm.tar.gz to the LCM host. Extract the package and run the installer:

```
tar xf bios-lcm.tar.gz
bios-lcm/install_lcm.sh
```

The LCM runs under a python virtual env `/isima/lcm/lcm_venv` created by the installer. Activate it:

```
source /isima/lcm/lcm_venv/bin/activate
```

#### Edit Configuration Files
The installer places the files necessary for LCM under directory `/isima/lcm`. Sub directories
are created as following:

- `env` -- Configuration files
- `images` -- bi(OS) component images
- `lcm` -- LCM application directory
- `log` -- Operation logs
- `lcm_venv` -- Python virtual environment to run LCM

The directories `env` and `images` need manual preparation by the user.

Ensure the following files are populated correctly in the `/isima/lcm/env/` directory:

* hosts.yaml
* cluster_config.yaml
* web.cert.pem
* web.key.pem
* tenant.yaml

Edit them to make it work for your cluster. Most names in bi(OS) only allow alphanumeric characters and underscores.

##### hosts.yaml

1. All hosts must have the "ip" field. Starting from the example file, ensure that you update at least the IP addresses to match your environment.
1. For load balancer (web server) nodes if there is a separate public IP address, it should be specified in the "public_ip" field.
1. "user" and "password" fields are optional for all hosts. If a user is not specified, the current user on the lcm machine is used. If password-less SSH has been set up (e.g. using keys/certificates) then a password is not necessary.
1. All hosts should run Ubuntu 22.04 LTS.
1. It should be possible to ssh from the lcm machine to all other hosts using their “private_host” name/IP, e.g. ssh private_host should succeed. This may need entries to be added to ~/.ssh/authorized_keys file on each of the other hosts.
1. The LCM machine must have access to download bi(OS) build files and docker images from the public internet. Credentials to download them will be provided by Isima separately.


##### cluster_config.yaml

1. `cluster_dns_name` should be set to the DNS name assigned to this cluster. The DNS name should point to the IP addresses of the compute VMs assigned to the `lb` role in hosts.yaml.

##### web.cert.pem and web.key.pem

An SSL/TLS certificate in .pem format needs to be created for the DNS name that will be used for the bi(OS) cluster. It is not necessary for this DNS name to be open to the public internet. The SSL certificate can be generated using any standard process for SSL certificates within the company, or by using public resources such as Let's Encrypt.

###### Instructions if using Let's Encrypt

In the below commands, replace <cluster_dns_name> with the actual full domain name you want to use for the bios cluster, e.g. `bios.example.com`.

```
sudo apt update
sudo apt install -y certbot
sudo certbot certonly --manual --preferred-challenges dns -d <cluster_dns_name> -d *.<cluster_dns_name>
```

Then follow the instructions on the terminal to add two TXT DNS entries to verify that you own the domain name. Add the first TXT DNS entry to your DNS server, then press Enter to get the second TXT value to add. You can add multiple data entries for the same name. After adding both TXT entries to your DNS server, wait for some time for the DNS records to propagate before pressing Enter to continue certbot.

The generated certificate and key files can be found under `/etc/letsencrypt/` directory. The certificate is usually named `fullchain.pem` and the key is usually named `privkey.pem`. Copy them to `/isima/lcm/env/` with names `web.cert.pem` and `web.key.pem`.


##### tenant.yaml

This is used to create a tenant in the bi(OS) cluster. There can be multiple such files to create multiple tenants, named as `tenant*.yaml`.

1. `tenant_name`: a name for the tenant; this cannot be changed later.
1. `users`: these initial users are created in the tenant. Update the passwords.
1. `load`: if present, a few example signals and contexts are created in the tenant and a synthetic load generator is started that ingests data into these streams.
1. `bios-sql`: if present, SQL access is enabled for this tenant. In order for this to work, create a DNS entry in the form `<tenant_name>-sql.<cluster_dns_name>` (e.g. `tenant1-sql.bios.example.com`) and point it to the same IP addresses as `<cluster_dns_name>`.
1. `bios-integrations`: if present, apps to ingest data from various sources are deployed for this tenant. Configuration for these apps is done via the bi(OS) UI or API.

#### Prepare Image Files

LCM picks up component images from the directory `/isima/lcm/images` during the installation.
Following table lists necessary images:

| Component         | Role                                  | Image type                | Typical image name                 | Source repository |
| ----------------- | ------------------------------------- | ------------------------- | ---------------------------------- | ----------------- |
| bios              | server                                | Docker image              | bios-<version>.tar.gz              | bios              |
| bios-storage      | database                              | Docker image              | bios-storage-<version>.tar.gz      | bios              |
| bioslb            | load balancer                         | Docker image              | bioslb-<version>.tar.gz            | bios              |
| bios-maintainer   | maintainer                            | Docker image              | bios-maintainer-<version>.tar.gz   | bios              |
| bios-integrations | integrations                          | Docker image              | bios-integrations-<version>.tar.gz | bios-integrations |
| bios-sql          | SQL server                            | Docker image              | bios-sql-<version>.tar.gz          | bios-sql          |
| bios-ui           | UI app                                | Web resources             | bios-ui-<version>.tar.gz           | bios-ui           |
| bios-docs         | documentation                         | Web resources             | bios-docs-<version>tar.gz          | bios-ui           |
| fluentbit         | monitoring package based on FluentBit | self-extracting installer | fluentbit-self-install.bsx         | lcm               |

##### Prepare Docker Images

Build docker images using the source repositories listed above. Save the images by `docker save`
command, for example,

```
docker save bios:1.2.0 | gzip -c > bios-1.2.0.tar.gz
```

A docker image type must be provided as a tar or tar.gz file.

##### Prepare Web Resource Tar Balls

The repository `bios-ui` builds necessary images by `build.sh` under directory `target`.
Pick them up and place in the LCM host at `/isima/lcm/images`.

##### Prepare Monitoring Package

Build the package in the LCM repository. The builder depends on repository `bios-fluentbit`.
Check out and build it first. Then, in the lcm repository, run `node-monitoring/build-fluentbit-installer.sh`.
The artifact is `build/fluentbit-self-install.bsx`. Place this file at `/isima/lcm/images` in the
LCM host.

#### Validate Inputs and Hosts

```
/isima/lcm/lcm/install_bios.py validate
```

#### Install bi(OS) Cluster

```
/isima/lcm/lcm/install_bios.py install
```

#### Create a tenant

```
/isima/lcm/lcm/create_tenant.py /isima/lcm/env/tenant.yaml
```

## Upgrading bi(OS) Components

Place the new image file in directory `/isima/lcm/images`.
Run `/isima/lcm/lcm/upgrade_bios.py` to upgrade biOS components. `--image-file` option should be
specified to determine which image to be used for upgrading. Note that absolute path is not accepted.
Specify the relative directory to `/isima/lcm/images`.

Execution example:

```
/isima/lcm/lcm/upgrade_bios.py --image-file bios-1.2.1.tar.gz bios
```

Supported components are:

- bios
- bios-storage
- bios-maintainer
- bios-integrations
- bios-sql
- bios

## Upgrading LCM

LCM can be upgraded from local development environment using the installation script `install_lcm.sh`.
