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

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd)"
DEFAULT_FLUENT_BIT_DIR="$(cd "${SCRIPT_DIR}/../fluent-bit-bios"; pwd)"

set -e

if [ "$0" = "--help" ]; then
  echo "Usage: "$(basename "$0")" [--help] [fluent-bit-dir]"
  echo "Builds a biOS monitoring tool installer. The package requires bios-fluent-bit"
  echo "repository located at directory ${DEFAULT_FLUENT_BIT_DIR}."
  echo "The repository location can be overridden by specifying parameter "'[fluent-bit-dir]'"."
  exit 1
fi

FLUENT_BIT_DIR=$1
if [ -z "${FLUENT_BIT_DIR}" ]; then
    FLUENT_BIT_DIR=${DEFAULT_FLUENT_BIT_DIR}
fi

if [ ! -d "${FLUENT_BIT_DIR}" ]; then
  echo "ERROR: Fluent bit repository "${FLUENT_BIT_DIR}" is missing"
  exit 1
fi

FLUENT_BIT_FILE=$(find "${FLUENT_BIT_DIR}" -name 'td-agent-bit_*_amd64.deb')
if [ -z "${FLUENT_BIT_FILE}" ]; then
    cd ${FLUENT_BIT_DIR}/packaging
    CMAKE_INSTALL_PREFIX=/usr FLB_TRACE=Off FLB_DISTRO=ubuntu/22.04 ./build.sh
    FLUENT_BIT_FILE=$(find "${FLUENT_BIT_DIR}" -name 'td-agent-bit_*_amd64.deb')
fi
if [ -z "${FLUENT_BIT_FILE}" ]; then
    echo -e "\nERROR: Failed to build FluentBit\n"
    exit 1
fi

TEMPDIR="${SCRIPT_DIR}/temp"
rm -rf "${TEMPDIR}"
cp -r "${SCRIPT_DIR}/resources" "${TEMPDIR}"
cp "${FLUENT_BIT_FILE}" "${TEMPDIR}"

"${SCRIPT_DIR}/packager/make-self.sh" -d "${TEMPDIR}" -n fluentbit-self-install
rm -r "${TEMPDIR}"
