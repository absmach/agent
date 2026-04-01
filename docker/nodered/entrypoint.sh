#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Generates flows_cred.json from environment variables before starting Node-RED.
# Required env vars:
#   MG_AGENT_CLIENT_ID      - Magistrala client ID (used as MQTT username)
#   MG_AGENT_CLIENT_SECRET  - Magistrala client secret (used as MQTT password)

set -e

if [ ! -f /data/.initialized ]; then
    cp /seed/settings.js /data/settings.js
    cp /seed/flows.json  /data/flows.json
    touch /data/.initialized
fi

cat > /data/flows_cred.json << EOF
{
    "mqtt-broker-config": {
        "user": "${MG_AGENT_CLIENT_ID}",
        "password": "${MG_AGENT_CLIENT_SECRET}"
    }
}
EOF

exec /usr/src/node-red/node_modules/.bin/node-red --settings /data/settings.js "$@"
