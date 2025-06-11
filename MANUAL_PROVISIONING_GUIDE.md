
# bi(OS) Service Cluster Manual Provisioning Guide

A bi(OS) cluster needs multiple hosts to run a distributed data platform.

LCM can take care of provisioning necessary VM instances in Google Cloud
(See [Provisioner User Guide](PROVISIONER.md)), but you need to provision the hosts manually
to set up a service cluster for other cloud services
or on-prem environments. This document describes the steps to provision bi(OS) service hosts
manually. This document is useful also for understanding the architecture of bi(OS) service
cluster.

## What Types of Hosts Are Necessary?
Four categories of hosts are necessary which are called roles:

- lcm
- storage
- lb
- compute

The following table lists summary of the roles. Provision them manually. The details of the roles
will be explained in the last section.

| Role    | Purpose                               | Number of hosts      | Least # CPUs | Least memory | Required large storages volumes                                               |
| ------- | ------------------------------------- | -------------------- | ------------ | ------------ | ----------------------------------------------------------------------------- |
| lcm     | to run LCM and bios-maintainer        | 1                    | 1            | 4 GB         | 1 for application logs                                                        |
| storage | to run bios and bios-storage          | 3 * N, N >= 1        | 8            | 16 GB        | 1 for DB logs,<br>1 for app logs (may be consolidated),<br> >= 1 for DB files |
| lb      | to run load balancer(s)               | 1 or more            | 2            | 4 GB         | 1 for application logs                                                        |
| compute | to run bios-integrations and bios-sql | 0 or more (optional) | 2            | 8 GB         | 1 for application logs                                                        |

## Things to Consider for Provisioning
### Number of Hosts and Their Sizes

Number and sizes of the hosts to provision have to be determined first. The necessary
scale vary depending on the expected traffic.  The following is a set of sizings of a reference
environment that is capable to accept 5000 events per second constantly (TODO: check the numbers).

| Role    | # hosts | # CPUs | Memory | Storage                                                                    |
| ------- | ------- | ------ | ------ | -------------------------------------------------------------------------- |
| lcm     | 1       | 4      | 16     | 30 GB                                                                      |
| storage | 3       | 16     | 122    | 256 GB for system<br>256 GB for DB & app logs<br>2x1.9TB nVME for DB files |
| lb      | 2       | 2      | 32     | 250 GB                                                                     |
| compute | 2       | 4      | 16     | 250 GB                                                                     |

### Network
In order to manage a bi(OS) service cluster by LCM, all the service hosts should be accessible by
LCM via SSH without password, including the LCM host itself.

The most typical way is to create an SSH key on LCM and put the public key to each hosts, i.e., run

```
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub
```

then put the public key to `~/.ssh/authorized_keys` for each service host.

Service hosts communicate each other by other means.  Open following ports in the firewalls of the
hosts.  It is recommended to open all ports to the local network in the compute hosts because
each of bios-integrations and bios-sql containers has individual service ports and they are
determined dynamically by LCM or bi(OS) server.

| Role    | Port                     | Protocol/purpose                                                     | Accessed by       |
| ------- | ------------------------ | -------------------------------------------------------------------- | ----------------- |
| lb      | 443                      | HTTPS                                                                | public internet   |
| storage | 443                      | HTTPS (HTTP/2)                                                       | all service hosts |
| storage | 4433                     | QUIC (HTTP/3)                                                        | all service hosts |
| storage | 9443                     | HTTPS (HTTP/1)                                                       | all service hosts |
| storage | 10109                    | Cassandra DB access                                                  | storage, lcm      |
| storage | 10105                    | Cassandra JMX access                                                 | storage, lcm      |
| compute | changed by configuration | bios-integrations webhook listener (HTTP/HTTPS) default 8081 or 8443 | lb, storage, lcm  |
| compute | changed by configuration | bios-integrations management listener (HTTP) default 9001            | storage, lcm      |
| compute | changed by configuration | bios-sql listener                                                    | lb, storage, lcm  |

### Storage

All host should have enough storage space for application logs.

Storage hosts are required to have extra storage volumes for

- database log -- one volume, SSD storage recommended
- database files -- at least volume, nVME storage(s) are recommended

You do not have to initialize and mount these volumes in the provisioning time. The bi(OS) installer
in the LCM can take care of it.

##### Database log
- type: SSD storage in production usage
- size: TBD
- configuration in cluster_config.yaml:\
  `logs_volume` - Storage device name (e.g. /dev/sdb)\
  `logs_mountpoint` - Log storage directory

Volume and mount point names must be the same among the storage nodes.

For testing purpose, it is fine just to provide `logs_mountpoint` with some plain storage.

##### Database files
One or more database file storage areas are required.

- type: NVMe storages in production usage
- site: TBD
- configuration in cluster_config.yaml:\
  `data_volumes` - Storage device name\
  `data_dir_prefix` - Log storage directory

Volume and mount point names must be the same among the storage nodes.

Example configuration:

```
data_volumes:
  - /dev/nvme0n1
  - /dev/nvme0n2
data_dir_prefix: /mnt/disks/data
``` 

LCM would initialize and mount the volumes if the data directories `${data_dir_prefix}N` are missing where `N` is data volume index number starting with `1` (such as `/mnt/disks/data1`, `/mnt/disks/data2`, and so on).

It is fine in a test environment just to make these directory manually without providing the special storages.
