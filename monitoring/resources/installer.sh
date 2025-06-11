#!/usr/bin/env bash
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

function install_fluentbit()
{
  sudo systemctl stop td-agent-bit || true
  sudo apt-get purge -y td-agent-bit || true
  sudo rm -f /etc/td-agent-bit/td-agent-bit.conf
  sudo apt-get update

  AGENT_VERSION=1.9.9

  sudo apt-get install -y libpq5 util-linux
  sudo apt-get install -y ./td-agent-bit_${AGENT_VERSION}_amd64.deb
}

function setup_fluentbit()
{
  sudo systemctl enable td-agent-bit
  envsubst < isima-env.config > isima-env.conf
  for f in *.conf
  do
      sudo cp $f /etc/td-agent-bit/
  done
  sudo systemctl daemon-reload
  sudo systemctl start td-agent-bit
}

function show_install()
{
  sudo cat /etc/td-agent-bit/isima-env.conf
  sudo systemctl status td-agent-bit
}

install_fluentbit
setup_fluentbit
show_install
