#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Generates flows_cred.json from bootstrap/env values before starting Node-RED.
# Required env vars:
#   MG_AGENT_CLIENT_ID      - Magistrala client ID (used as MQTT username)
#   MG_AGENT_CLIENT_SECRET  - Magistrala client secret (used as MQTT password)

set -e

CONFIG_FILE="${MG_AGENT_CONFIG_FILE:-/seed/config.toml}"

toml_value() {
    if [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi

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

bootstrap_exports() {
    if [ -z "${MG_AGENT_BOOTSTRAP_URL:-}" ] || [ -z "${MG_AGENT_BOOTSTRAP_EXTERNAL_ID:-}" ] || [ -z "${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY:-}" ]; then
        return 0
    fi

    node <<'NODE'
const http = require("http");
const https = require("https");

const baseURL = process.env.MG_AGENT_BOOTSTRAP_URL || "";
const bootstrapID = process.env.MG_AGENT_BOOTSTRAP_EXTERNAL_ID || "";
const bootstrapKey = process.env.MG_AGENT_BOOTSTRAP_EXTERNAL_KEY || "";
const skipTLS = process.env.MG_AGENT_BOOTSTRAP_SKIP_TLS === "true";
const retries = Math.max(parseInt(process.env.MG_AGENT_BOOTSTRAP_RETRIES || "5", 10) || 1, 1);
const retryDelaySec = Math.max(parseInt(process.env.MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS || "10", 10) || 0, 0);

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function request(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === "https:" ? https : http;
    const options = {
      headers: { Authorization: `Client ${bootstrapKey}` },
      timeout: 30000
    };

    if (parsed.protocol === "https:") {
      options.agent = new https.Agent({ rejectUnauthorized: !skipTLS });
    }

    const req = client.get(parsed, options, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        if (res.statusCode >= 400) {
          reject(new Error(`bootstrap returned HTTP ${res.statusCode}`));
          return;
        }
        resolve(data);
      });
    });

    req.on("timeout", () => req.destroy(new Error("bootstrap request timed out")));
    req.on("error", reject);
  });
}

async function fetchBootstrap() {
  const url = `${baseURL.replace(/\/+$/, "")}/${bootstrapID.replace(/^\/+/, "")}`;
  let lastErr;

  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      return await request(url);
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        console.error(`Fetching bootstrap failed: ${err.message}; retrying in ${retryDelaySec}s`);
        await sleep(retryDelaySec * 1000);
      }
    }
  }

  throw lastErr;
}

(async () => {
  try {
    const body = JSON.parse(await fetchBootstrap());
    let content = body.content === undefined ? body : body.content;
    if (typeof content === "string") {
      content = JSON.parse(content);
    }

    const mqtt = content.mqtt || {};
    const telemetry = content.telemetry || {};
    const channels = content.channels || {};

    const values = {
      MG_AGENT_CLIENT_ID: process.env.MG_AGENT_CLIENT_ID || mqtt.client_id || mqtt.username || "",
      MG_AGENT_CLIENT_SECRET: process.env.MG_AGENT_CLIENT_SECRET || mqtt.secret || mqtt.password || "",
      MG_AGENT_DOMAIN_ID: process.env.MG_AGENT_DOMAIN_ID || content.domain_id || "",
      MG_AGENT_CHANNEL: process.env.MG_AGENT_CHANNEL || telemetry.channel_id || channels.data_id || channels.id || "",
      MG_AGENT_CTRL_CHANNEL: process.env.MG_AGENT_CTRL_CHANNEL || channels.ctrl_id || channels.id || "",
      MG_AGENT_MQTT_URL: process.env.MG_AGENT_MQTT_URL || mqtt.url || ""
    };

    for (const [key, value] of Object.entries(values)) {
      if (value !== "") {
        console.log(`${key}=${shellQuote(value)}; export ${key};`);
      }
    }
  } catch (err) {
    console.error(`Failed to load bootstrap config for Node-RED: ${err.message}`);
    process.exit(1);
  }
})();
NODE
}

BOOTSTRAP_EXPORTS="$(bootstrap_exports)"
if [ -n "$BOOTSTRAP_EXPORTS" ]; then
    eval "$BOOTSTRAP_EXPORTS"
fi

if [ -f "$CONFIG_FILE" ]; then
    MG_AGENT_CLIENT_ID="${MG_AGENT_CLIENT_ID:-$(toml_value mqtt username)}"
    MG_AGENT_CLIENT_SECRET="${MG_AGENT_CLIENT_SECRET:-$(toml_value mqtt password)}"
    MG_AGENT_DOMAIN_ID="${MG_AGENT_DOMAIN_ID:-$(toml_value "" domain_id)}"
    MG_AGENT_CHANNEL="${MG_AGENT_CHANNEL:-$(toml_value channels id)}"
    MG_AGENT_CTRL_CHANNEL="${MG_AGENT_CTRL_CHANNEL:-$(toml_value channels ctrl_id)}"
    MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL:-$(toml_value mqtt url)}"
fi
MG_AGENT_CTRL_CHANNEL="${MG_AGENT_CTRL_CHANNEL:-$MG_AGENT_CHANNEL}"

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
export MG_AGENT_CTRL_CHANNEL
export MQTT_HOST
export MQTT_PORT
export MQTT_USETLS
export MQTT_SKIP_TLS

if [ ! -f /data/.initialized ]; then
    cp /seed/nodered/settings.js /data/settings.js
    cp /seed/nodered/flows.json  /data/flows.json
    touch /data/.initialized
fi

# Patch flows.json at every start using JSON-aware updates:
#  - mqtt-broker nodes get host/port/TLS/client credentials from bootstrap/env
#  - mqtt out nodes keep valid broker config references
#  - function/topic strings get the provisioned Magistrala MQTT message topic
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
const dataTopic = `m/${domainID}/c/${channelID}/msg`;
const topicPattern = /m\/[^/"'\s]*\/c\/[^/"'\s]*\/(?:data|msg)/g;

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

# Publish heartbeat so Node-RED appears in the agent's services list.
# Runs as a background Node.js process using the mqtt package bundled with Node-RED.
node <<'HEARTBEAT' &
const path = require("path");

let mqttLib;
try {
  mqttLib = require(path.join("/usr/src/node-red/node_modules", "mqtt"));
} catch (e) {
  process.stderr.write("mqtt package not found, heartbeat disabled\n");
  process.exit(0);
}

const host        = process.env.MQTT_HOST             || "";
const port        = parseInt(process.env.MQTT_PORT    || "1883", 10);
const useTLS      = process.env.MQTT_USETLS           === "true";
const skipTLS     = process.env.MQTT_SKIP_TLS         === "true";
const clientID    = process.env.MG_AGENT_CLIENT_ID    || "";
const secret      = process.env.MG_AGENT_CLIENT_SECRET || "";
const domainID    = process.env.MG_AGENT_DOMAIN_ID    || "";
const ctrlChannel = process.env.MG_AGENT_CTRL_CHANNEL || "";

if (!host || !domainID || !ctrlChannel) {
  process.stderr.write("Incomplete MQTT config, heartbeat disabled\n");
  process.exit(0);
}

// Publish at 80% of the agent heartbeat interval to stay safely within the window.
// Parse Go duration strings: e.g. "1m30s", "2h", "30s", "10s".
function parseDurationSec(s) {
  let total = 0;
  const re = /(\d+(?:\.\d+)?)(h|m|s|ms)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const v = parseFloat(m[1]);
    switch (m[2]) {
      case "h":  total += v * 3600; break;
      case "m":  total += v * 60;   break;
      case "s":  total += v;        break;
      case "ms": total += v / 1000; break;
    }
  }
  return total > 0 ? total : 10;
}
const intervalSec = parseDurationSec(process.env.MG_AGENT_HEARTBEAT_INTERVAL || "10s");
const publishMs   = Math.max(Math.floor(intervalSec * 0.8) * 1000, 1000);

const brokerURL = (useTLS ? "mqtts" : "mqtt") + "://" + host + ":" + port;
const topic     = "m/" + domainID + "/c/" + ctrlChannel + "/services/nodered/heartbeat";
const payload   = JSON.stringify([{"bn": "nodered:", "n": "service_type", "vs": "nodered"}]);

const client = mqttLib.connect(brokerURL, {
  clientId:          clientID + "-hb",
  username:          clientID,
  password:          secret,
  rejectUnauthorized: !skipTLS,
  reconnectPeriod:   5000,
});

client.on("connect", function () {
  var publish = function () { client.publish(topic, payload, {qos: 0, retain: false}); };
  publish();
  setInterval(publish, publishMs);
});

client.on("error", function (err) {
  process.stderr.write("Heartbeat error: " + err.message + "\n");
});
HEARTBEAT

exec /usr/src/node-red/node_modules/.bin/node-red --settings /data/settings.js "$@"
