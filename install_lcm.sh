#!/bin/bash
##
## Copyright (C) 2025 Isima, Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

set -e

SCRIPT_DIR="$(cd "$(dirname $0)"; pwd)"
LCM_SRC="${SCRIPT_DIR}"
LCM_ROOT=/isima/lcm
LCM_VENV=lcm_venv

echo -en "\n ... Setting up the LCM location at ${LCM_ROOT} ..."
if [ -e "${LCM_ROOT}" ]; then
    INITIAL_INSTALL=0
else
    INITIAL_INSTALL=1
fi
sudo mkdir -p ${LCM_ROOT}
sudo chown -R $(id -u):$(id -g) ${LCM_ROOT}
cp -r ${LCM_SRC}/lcm ${LCM_ROOT}/
echo " done"

echo -e "\n ... Installing required software ...\n"

sudo apt-get update
sudo apt-get install -y --no-upgrade python3 python3-pip python3-dev python3-venv vim

python3 -m venv --prompt lcm ${LCM_ROOT}/${LCM_VENV}
source ${LCM_ROOT}/${LCM_VENV}/bin/activate
python3 -m pip install --upgrade pip
pip3 install -r ${LCM_SRC}/requirements.txt
pip3 install ${LCM_SRC}/bios_sdk-*.whl

echo -e "\n ... Done installing required software ...\n"

mkdir -p ${LCM_ROOT}/env
# Copy example config files if environment is not already populated with config files.
# This enables downloading newer LCM code without overwriting existing environment files.
if test ! -f ${LCM_ROOT}/env/hosts.yaml; then
    cp ${LCM_ROOT}/lcm/example_configs/hosts.yaml ${LCM_ROOT}/env/
    echo && echo ------ !!!    Please update ${LCM_ROOT}/env/hosts.yaml. This is REQUIRED   !!!
fi
if test ! -f ${LCM_ROOT}/env/web.cert.pem; then
    echo && echo ------ !!!    Please create files ${LCM_ROOT}/env/web.cert.pem and web.key.pem with the DNS SSL certificate. This is REQUIRED   !!!
fi
if test ! -f ${LCM_ROOT}/env/cluster_config.yaml; then
    cp ${LCM_ROOT}/lcm/default_configs/default_cluster_config.yaml ${LCM_ROOT}/env/cluster_config.yaml
    echo && echo ------ !!!    Please review and update ${LCM_ROOT}/env/cluster_config.yaml This is REQUIRED   !!!
fi

if test ! -f ${LCM_ROOT}/env/alerts.yaml; then
    cp ${LCM_ROOT}/lcm/example_configs/alerts.yaml ${LCM_ROOT}/env/
    echo && echo ------ Please review and update ${LCM_ROOT}/env/alerts.yaml
fi

# The following feature is untested. Enable them after being tested.
# if test ! -f ${LCM_ROOT}/env/tenant.yaml; then
#     cp ${LCM_ROOT}/lcm/example_configs/tenant.yaml ${LCM_ROOT}/env/
#     echo && echo ------ Please review and update ${LCM_ROOT}/env/tenant.yaml.
# fi

INSTALLATION_INSTRUCTION="

####################

  After setting the configuration files above, the LCM is ready to install bi(OS).
  Run the following commands to start installing:

    source ${LCM_ROOT}/lcm_venv/bin/activate
    ${LCM_ROOT}/lcm/install_bios.py install

  For detailed instructions, see ${LCM_ROOT}/lcm/README.md

####################"

if [ ${INITIAL_INSTALL} = 1 ]; then
    echo "${INSTALLATION_INSTRUCTION}"
fi
