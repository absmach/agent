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

# Patch flows.json at every start:
#  - clientid: append -nr so Node-RED has a unique MQTT clientid (same auth, no session conflict)
#  - topic: inject the provisioned domain and data channel
sed -i \
    -e "s/\"clientid\": \"[^\"]*\"/\"clientid\": \"${MG_AGENT_CLIENT_ID}-nr\"/" \
    -e "s|m/[^/]*/c/[^/]*/data|m/${MG_AGENT_DOMAIN_ID}/c/${MG_AGENT_CHANNEL}/data|g" \
    /data/flows.json

exec /usr/src/node-red/node_modules/.bin/node-red --settings /data/settings.js "$@"
