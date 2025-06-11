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

#decompress script for bash
echo ""
echo "Self Extracting Installer"
echo ""

#bash strict mode
set -eo pipefail

PKGNAME=$(basename $0 | cut -d'.' -f1)

if [ -n "${1}" ]; then
  PREFIX=$(cd "$(dirname $1)" ; pwd -P)
  BASENAME=$(basename $1)
  DST_PREFIX=${PREFIX}/${BASENAME}
else
  DST_PREFIX=/tmp/${PKGNAME}
fi
export TMPDIR=`mktemp -d /tmp/selfextract.XXXXXX`

ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`

tail -n+$ARCHIVE $0 | tar xzv -C $TMPDIR

CURDIR=`pwd`
cd $TMPDIR
bash ./install.sh  ${PKGNAME} ${DST_PREFIX}
retcode=$?

cd $CURDIR
rm -rf $TMPDIR

exit $retcode
__ARCHIVE_BELOW__
