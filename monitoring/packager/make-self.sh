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

# script to create self extracting bash script given a payload
TMPDIR=$(mktemp -d -t tmp.XXXXXXXXXX)
#function finish {
#  rm -rf "$TMPDIR"
#}
#trap finish EXIT

function usage()
{
 echo "Usage: $(basename $0) -d <dir> -f <file-1> -f <file-2> -f <file-n>  -n <pkgname>"
   cat <<HELP
   Usage: make-self [options]
          make-self -d <dir> -f <file-1> -f <file-2> -f <file-n>  -n <pkgname>"
   packages the files in the directory <dir> and files <file..> in to self extracting
   bash script, which can be copied in to any machine and expanded using the command
   The generated file is build/<package.bsx>
   the expansion of the file also call cusomized installer.sh embedded in the file, so
   that end user can customize it the way they want it.
   bash <package>.bsx
   Examples:
HELP
 exit 1
}
#exclude build,git,target files in directories
EXCLUDE="--exclude .git --exclude build"
MYSRC_DIR=$(dirname "$0")

#parse the command line
declare -a PAYLOAD_FILES=()
while getopts "d:f:n:" OPTION; do
  case "$OPTION" in 
     d)  PAYLOAD_DIR=${OPTARG}
        ;;
     f) PAYLOAD_FILES+=("${OPTARG}")
        ;;
     n)  PKGNAME=${OPTARG}
        ;;
     ?) usage 
      ;;
  esac
done
shift "$(($OPTIND -1))"

#check the input parameters
[[  -d "${PAYLOAD_DIR}" || ${#PAYLOAD_FILES[@]} -ne 0  ]] || usage
[[ -n "${PKGNAME}" ]] || usage

PAYLOAD_TAR=${TMPDIR}/${PKGNAME}.tar
rm -rf ${PAYLOAD_ZIP}

#build the tar file for build the selfextracting file
for f in "${PAYLOAD_FILES[@]}"
do
  tar rvf ${PAYLOAD_TAR} $f
done

if [[ -d ${PAYLOAD_DIR} ]]; then
   tar rvf ${PAYLOAD_TAR} -C ${PAYLOAD_DIR} .;
fi


#add the default intaller
(tar rvf ${PAYLOAD_TAR}  -C ${MYSRC_DIR} install.sh)

if [ -e  ${PAYLOAD_TAR} ]; then
    gzip ${PAYLOAD_TAR}

    mkdir -p build
    if [ -e "${PAYLOAD_TAR}.gz" ]; then
        cat ${MYSRC_DIR}/make-decompress.sh ${PAYLOAD_TAR}.gz > build/${PKGNAME}.bsx
    else
        echo "${PAYLOAD_TAR}.gz does not exist"
        exit 1
    fi
else
    echo "${PAYLOAD_TAR}.gz does not exist"
    exit 1
fi
echo "build/${PKGNAME}.bsx created"
exit 0
