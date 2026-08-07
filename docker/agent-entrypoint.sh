#!/bin/sh
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

set -eu

config_path="${MG_AGENT_CONFIG_PATH:-/var/lib/agent/agent-config.json}"
seed_path="${MG_AGENT_CONFIG_SEED_PATH:-/etc/agent/agent-config.json}"

mkdir -p "$(dirname "$config_path")"
if [ ! -s "$config_path" ] && [ -f "$seed_path" ]; then
    cp "$seed_path" "$config_path"
    chmod 600 "$config_path"
fi

socat -d -d \
    pty,raw,echo=0,link=/dev/ttyV0 \
    pty,raw,echo=0,link=/dev/ttyV1 &

exec /exe
