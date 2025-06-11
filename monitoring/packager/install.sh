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
echo "Running Base Installer"
PKGNAME=${1}
DSTDIR=${2}
mkdir -p ${DSTDIR}
cp -r ${TMPDIR}/* ${DSTDIR}

CUSTOM_INSTALLER=${DSTDIR}/installer.sh
CUSTOM_CONFIG=${DSTDIR}/installer.config
(cd ${DSTDIR};rm install.sh)
if [ -f ${CUSTOM_INSTALLER} ]; then
  echo "Running Installer ${CUSTOM_INSTALLER}"
  ( cd ${DSTDIR};
    ${CUSTOM_INSTALLER}
    if [[ -f ${CUSTOM_CONFIG} ]]; then
      source ${CUSTOM_CONFIG}
    fi
    rm $CUSTOM_INSTALLER
  )
fi
echo "Completed installation ${PKGNAME}"
