#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Generates flows_cred.json from environment variables before starting Node-RED.
# Required env vars:
#   MG_AGENT_CLIENT_ID      - Magistrala client ID (used as MQTT username)
#   MG_AGENT_CLIENT_SECRET  - Magistrala client secret (used as MQTT password)

set -e

CONFIG_FILE="${MG_AGENT_CONFIG_FILE:-/seed/config.toml}"

toml_value() {
    section="$1"
    key="$2"
    awk -v section="$section" -v key="$key" '
        /^[[:space:]]*\[/ {
            current=$0
            gsub(/^[[:space:]]*\[/, "", current)
            gsub(/\][[:space:]]*$/, "", current)
            next
        }
        {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            split(line, parts, "=")
            found=parts[1]
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", found)
            if (found == key && current == section) {
                value=substr(line, index(line, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                gsub(/^"|"$/, "", value)
                print value
                exit
            }
        }
    ' "$CONFIG_FILE"
}

if [ -f "$CONFIG_FILE" ]; then
    MG_AGENT_CLIENT_ID="${MG_AGENT_CLIENT_ID:-$(toml_value mqtt username)}"
    MG_AGENT_CLIENT_SECRET="${MG_AGENT_CLIENT_SECRET:-$(toml_value mqtt password)}"
    MG_AGENT_DOMAIN_ID="${MG_AGENT_DOMAIN_ID:-$(toml_value "" domain_id)}"
    MG_AGENT_CHANNEL="${MG_AGENT_CHANNEL:-$(toml_value channels id)}"
    MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL:-$(toml_value mqtt url)}"
fi

MQTT_HOST=""
MQTT_PORT=""
MQTT_SCHEME=""
MQTT_USETLS="false"
if [ -n "$MG_AGENT_MQTT_URL" ]; then
    MQTT_SCHEME="${MG_AGENT_MQTT_URL%%://*}"
    mqtt_addr="${MG_AGENT_MQTT_URL#*://}"
    mqtt_addr="${mqtt_addr%%/*}"
    MQTT_HOST="${mqtt_addr%%:*}"
    MQTT_PORT="${mqtt_addr##*:}"
    if [ "$MQTT_PORT" = "$MQTT_HOST" ]; then
        MQTT_PORT="1883"
    fi
    case "$MQTT_SCHEME" in
        ssl|tls|mqtts)
            MQTT_USETLS="true"
            ;;
    esac
fi

MQTT_SKIP_TLS="${MG_AGENT_MQTT_SKIP_TLS:-$(toml_value mqtt skip_tls_ver)}"
export MG_AGENT_CLIENT_ID
export MG_AGENT_CLIENT_SECRET
export MG_AGENT_DOMAIN_ID
export MG_AGENT_CHANNEL
export MQTT_HOST
export MQTT_PORT
export MQTT_USETLS
export MQTT_SKIP_TLS

if [ ! -f /data/.initialized ]; then
    cp /seed/nodered/settings.js /data/settings.js
    cp /seed/nodered/flows.json  /data/flows.json
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

# Patch flows.json at every start using JSON-aware updates:
#  - mqtt-broker nodes get host/port/TLS/client credentials from TOML/env
#  - mqtt out nodes keep valid broker config references
#  - function/topic strings get the provisioned Magistrala data topic
node <<'NODE'
const fs = require("fs");

const flowFile = "/data/flows.json";
const credFile = "/data/flows_cred.json";
const tlsID = "magistrala-agent-tls";

const clientID = process.env.MG_AGENT_CLIENT_ID || "";
const clientSecret = process.env.MG_AGENT_CLIENT_SECRET || "";
const domainID = process.env.MG_AGENT_DOMAIN_ID || "";
const channelID = process.env.MG_AGENT_CHANNEL || "";
const mqttHost = process.env.MQTT_HOST || "";
const mqttPort = process.env.MQTT_PORT || "1883";
const mqttUseTLS = process.env.MQTT_USETLS === "true";
const mqttSkipTLS = process.env.MQTT_SKIP_TLS === "true";
const dataTopic = `m/${domainID}/c/${channelID}/data`;
const topicPattern = /m\/[^/"'\s]*\/c\/[^/"'\s]*\/data/g;

const flows = JSON.parse(fs.readFileSync(flowFile, "utf8"));
const nodes = Array.isArray(flows) ? flows : [];
const brokerIDs = new Set(nodes.filter((node) => node.type === "mqtt-broker").map((node) => node.id));

for (const node of nodes) {
  if (node.type === "mqtt-broker") {
    if (mqttHost) {
      node.broker = mqttHost;
    }
    node.port = mqttPort;
    node.clientid = clientID ? `${clientID}-nr` : node.clientid;
    node.usetls = mqttUseTLS;
    if (mqttUseTLS && mqttSkipTLS) {
      node.tls = tlsID;
    } else {
      delete node.tls;
    }
    node.credentials = { user: clientID, password: clientSecret };
  }

  if (node.type === "mqtt out" && brokerIDs.size === 1 && !brokerIDs.has(node.broker)) {
    node.broker = [...brokerIDs][0];
  }

  if (typeof node.func === "string") {
    node.func = node.func.replace(topicPattern, dataTopic);
  }

  if (typeof node.topic === "string") {
    node.topic = node.topic.replace(topicPattern, dataTopic);
  }
}

if (mqttUseTLS && mqttSkipTLS && !nodes.some((node) => node.id === tlsID)) {
  nodes.push({
    id: tlsID,
    type: "tls-config",
    name: "Magistrala MQTT TLS",
    cert: "",
    key: "",
    ca: "",
    certname: "",
    keyname: "",
    caname: "",
    servername: "",
    verifyservercert: false,
    alpnprotocol: ""
  });
}

const credentials = {};
for (const id of brokerIDs) {
  credentials[id] = { user: clientID, password: clientSecret };
}

fs.writeFileSync(flowFile, `${JSON.stringify(nodes, null, 4)}\n`);
fs.writeFileSync(credFile, `${JSON.stringify(credentials, null, 4)}\n`);
NODE

exec /usr/src/node-red/node_modules/.bin/node-red --settings /data/settings.js "$@"
