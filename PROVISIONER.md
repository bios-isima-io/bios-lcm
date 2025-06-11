# LCM Provisioner User Guide

## Obtaining the GCP credentials

Many of the LCM tools have capability to prepare resources in Google Cloud quickly,
such as TLS certificates and VM instances where bi(OS) components are installed.
In order to use the features, you need to obtain a GCP credentials.

You would need a json file containing gcp credentials for the following steps, which can be obtained
by going to the Service Accounts section of your GCP console, and looking for, or creating one if
there isn't one already, with OWNER permissions, ie the ability to create VMs, and generating an
access key for it in the Keys section. Please refer to the
[link here](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-console)
to know more about how to create one.

The following assumes you save the key in lcm/gcp_infra_creds.json

Besides this key which you need to authenticate yourself, there is another key the lcm code will use
to obtain copies of builds released by Isima. For this, you must request us to create a service
account and provide you with an access key for the same.

You must save this key as lcm/bios_image_reader_key.json

## Creating TLS Certificate

Once you determine your domain name to serve, create TLS certificate files in PEM format.

TODO: describe the manual steps

In case your domain is managed by Google Cloud DNS, you can create SSL certificate files
for a DNS name and copy the certificate files into a standard locations by following command:

```
cd lcm
./create_ssl_cert.py lcm-test.tieredfractals.com ./gcp_infra_creds.json verbose
```

## Provisioning Infrastructure

To provision a cluster in GCP, first create an infrastructure config yaml file.
See example in lcm/example_configs/infra_config.yaml to get started.
This contains the most commonly used properties. If more fine-grained control is desired,
you can include additional properties defined in lcm/default_configs/default_infra_config.yaml.

Also ensure you have the credentials file for an account that has permissions to create
VMs on the cloud, e.g. in file gcp_infra_creds.json

Example usage:

```
cd lcm
./provision.py gcp provision example_configs/infra_config.yaml ./gcp_infra_creds.json
```

Following this, update the hosts.yaml file with custom IP addresses for your machines if needed
and continue to add DNS entries as for it.

This assumes that you use the GCP DNS service for the domain name your organisation owns, and
the gcp credentials you specify here have permission to add entries to the DNS "managed zone". Both
the zone, and the gcp project in which it exists need to be specified in the infra_config.json file.

In case any of the assumptions above are not true for you, you would must manually add entries
for your biOS cluster subdomain in your DNS service.

Example usage:

```
cd lcm
./provision.py gcp update_dns_records example_configs/infra_config.yaml ./gcp_infra_creds.json $HOME/lcm/hosts.yaml
```

To provision a cluster in AWS, first create an infrastructure config yaml file.
See example in lcm/example_configs/infra_config.yaml to get started.
This contains the most commonly used properties. If more fine-grained control is desired,
you can include additional properties defined in lcm/default_configs/default_infra_config.yaml.

Ensure that you install the `awscli` tool and configure it with your credentials as the *LCM* tool uses
the AWS python SDK (**boto3**) which relies on it for authentication.

```
pip3 install awscli
aws configure
```

On running this, you would be prompted for an Access Key and a Secret Key which you must obtain
following the instructions
[here](https://docs.aws.amazon.com/powershell/latest/userguide/pstools-appendix-sign-up.html)
for an account which has privilege to create, manage and destroy EC2 instances.
It would also ask for your preferred region and output format, but those are optional.
Also ensure you have a copy of the private key for the keyPair "lcmKey" used for authentication on
VMs on the cloud with the correct file permissions (600), e.g. in file lcmKey.cer

Example usage:

```
cd lcm
./provision.py aws provision example_configs/infra_config.yaml ./lcmKey.cer
```

Following this, update the hosts.yaml file with custom IP addresses for your machines if needed
and continue to add DNS entries as for it.

You may use the following sub-command if you use google DNS. If not, it must be done manually.

Example usage:

```
cd lcm
./provision.py gcp update_dns_records example_configs/infra_config.yaml ./gcp_infra_creds.json $HOME/lcm/hosts.yaml
```

If the $HOME/lcm directory contains SSL certificate and key files named
web.cert.pem and web.key.pem, they will be copied to the newly created LCM VM
into /isima/lcm/env directory with names web.cert.pem and web.key.pem respectively.


A second command allows you to list the VMs created by LCM (those whose names begin
with the prefix specified in the yaml file).

Another command allows you to completely delete all resources provisioned by LCM.
Example usage:

```
cd lcm

./provision.py gcp list example_configs/infra_config.yaml ./gcp_infra_creds.json
./provision.py aws list example_configs/infra_config.yaml ./lcmKey.cer

./provision.py gcp obliterate example_configs/infra_config.yaml ./gcp_infra_creds.json
./provision.py aws obliterate example_configs/infra_config.yaml ./lcmKey.cer

```
