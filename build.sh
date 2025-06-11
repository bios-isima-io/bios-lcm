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

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd)"
ROOT="${SCRIPT_DIR}"
PYENV="${ROOT}/venv"
ARCHIVE_NAME=bios-lcm.tar.gz

# Check and set up prerequisites and submodule(s)

echo -en "\n... Checking if bi(OS) Python SDK exists ... "
cd "${ROOT}"
SDK_WHL=$(/bin/ls -1 bios_sdk-*.whl 2> /dev/null | tail -n 1)
if [ -z "${SDK_WHL}" ]; then
    # TODO: Install via PYPI in this case
    echo "ERROR: biOS Python SDK not found in directory ${ROOT}"
    exit 1
fi

echo -e "done\n"

echo -e "\n... Setting up submodule(s)\n"
git submodule init
git submodule update

echo -e "\n... Installing prerequisites in venv\n"
if [ ! -d ${PYENV} ]; then
    python3 -m venv ${PYENV}
fi
. ${PYENV}/bin/activate
python3 -m pip install -r ${ROOT}/requirements.txt
pip3 install "${ROOT}"/bios_sdk-*.whl

echo -e "\n... Finished installing prerequisites in venv\n"

echo -e "\n... Checking LCM code style\n"

isort --skip-gitignore --profile black ./lcm/
black --line-length=99 lcm/*.py lcm/lib/*.py lcm/bios_configs/*.py

pylint --rcfile=${ROOT}/.pylintrc \
       --disable=missing-docstring --disable=broad-except --disable=protected-access \
       --disable=broad-exception-raised --disable=fixme \
       --disable=too-many-locals --disable=too-many-statements --disable=too-many-arguments \
       --disable=too-many-branches --disable=too-many-lines --disable=too-many-instance-attributes \
       --disable=no-member --disable=too-many-public-methods --disable=f-string-without-interpolation \
       --ignore '.history,lcm/bios_configs/services/wordpress_analytics,lcm/bios_configs/services/store_enhancement' \
       lcm \
       || pylint-exit --error-fail --warn-fail $?

echo -e "\n... Done checking LCM code style\n"

echo -e "\n... Building monitoring tool installer\n"

${ROOT}/monitoring/build-fluentbit-installer.sh

echo -e "\n... Finished building monitoring tool installer\n"

echo -en "\n ... Packaging LCM ..."

rm -rf "${ROOT}/target"
LCM_PACKAGE_DIR="${ROOT}/target/bios-lcm"
mkdir -p "${LCM_PACKAGE_DIR}/lcm/lib"
cd "${ROOT}/lcm"
cp *.py ${LCM_PACKAGE_DIR}/lcm
cp lib/*.py ${LCM_PACKAGE_DIR}/lcm/lib/
cp -r bios_configs ${LCM_PACKAGE_DIR}/lcm/
cp -r default_configs ${LCM_PACKAGE_DIR}/lcm/
cp -r scripts ${LCM_PACKAGE_DIR}/lcm/
cp ${ROOT}/install_lcm.sh ${LCM_PACKAGE_DIR}/
cp ${ROOT}/requirements.txt ${LCM_PACKAGE_DIR}
cp "${ROOT}/${SDK_WHL}" ${LCM_PACKAGE_DIR}
cp -r example_configs ${LCM_PACKAGE_DIR}/lcm/
cd "${LCM_PACKAGE_DIR}/.."
tar -zcf "${ROOT}"/target/${ARCHIVE_NAME} bios-lcm > /dev/null

echo " done.

####################

  The LCM installation package has been created at ${ROOT}/target/${ARCHIVE_NAME}

  Put this file to the LCM host and run the following to install LCM:

    tar xf ${ARCHIVE_NAME}
    bios-lcm/install_lcm.sh

####################"
