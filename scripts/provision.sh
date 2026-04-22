#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Provision script for mock device environment.
# This script creates the necessary Magistrala resources (Clients, Channels)
# and configures a Rule Engine (RE) to store messages from the mock device.
#
# Prerequisites:
#   - A running Magistrala instance (self-hosted or cloud)
#   - curl and python3 available
#
# Environment variables:
#   MG_API          - Base API URL for all services (e.g., https://cloud.magistrala.absmach.eu/api)
#                     If set, overrides individual service API settings
#   MG_CLIENTS_API  - Clients service API base URL (default: http://localhost:9006)
#   MG_CHANNELS_API - Channels service API base URL (default: http://localhost:9005)
#   MG_RULES_API    - Rules service API base URL (default: http://localhost:9008)
#   MG_BOOTSTRAP_API - Bootstrap service API base URL (default: http://localhost:9013)
#   MG_DOMAIN_ID    - Domain ID (required)
#   MG_PAT          - Personal Access Token (required)
#   MG_AGENT_BOOTSTRAP_EXTERNAL_ID - External bootstrap ID for the device
#   MG_AGENT_BOOTSTRAP_EXTERNAL_KEY - External bootstrap key for the device
#   MG_AGENT_BOOTSTRAP_CLIENT_CERT - Optional PEM client certificate to store in bootstrap
#   MG_AGENT_BOOTSTRAP_CLIENT_KEY - Optional PEM client key to store in bootstrap
#   MG_AGENT_BOOTSTRAP_CA_CERT - Optional PEM CA certificate to store in bootstrap
#
# Usage (localhost):
#   export MG_PAT=pat_xxx
#   export MG_DOMAIN_ID=<domain-id>
#   ./provision.sh
#
# Usage (cloud):
#   export MG_API=https://cloud.magistrala.absmach.eu/api
#   export MG_PAT=pat_xxx
#   export MG_DOMAIN_ID=<domain-id>
#   ./provision.sh
#
# Override individual service APIs:
#   MG_CLIENTS_API=http://example.com:9006 ./provision.sh

set -euo pipefail

# Check if a unified API base URL is provided
if [ -n "${MG_API:-}" ]; then
  # Use the unified API base for all services
  MG_CLIENTS_API="${MG_CLIENTS_API:-${MG_API}}"
  MG_CHANNELS_API="${MG_CHANNELS_API:-${MG_API}}"
  MG_RULES_API="${MG_RULES_API:-${MG_API}}"
  MG_BOOTSTRAP_API="${MG_BOOTSTRAP_API:-${MG_API}}"
  DEFAULT_MQTT_URL="ssl://messaging.magistrala.absmach.eu:8883"
  DEFAULT_MQTT_SKIP_TLS="false"
else
  # Use individual service API defaults for localhost
  MG_CLIENTS_API="${MG_CLIENTS_API:-http://localhost:9006}"
  MG_CHANNELS_API="${MG_CHANNELS_API:-http://localhost:9005}"
  MG_RULES_API="${MG_RULES_API:-http://localhost:9008}"
  MG_BOOTSTRAP_API="${MG_BOOTSTRAP_API:-http://localhost:9013}"
  DEFAULT_MQTT_URL="ssl://host.docker.internal:8883"
  DEFAULT_MQTT_SKIP_TLS="true"
fi

MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL:-${DEFAULT_MQTT_URL}}"
MG_AGENT_MQTT_SKIP_TLS="${MG_AGENT_MQTT_SKIP_TLS:-${DEFAULT_MQTT_SKIP_TLS}}"
MG_AGENT_MQTT_MTLS="${MG_AGENT_MQTT_MTLS:-false}"
MG_AGENT_MQTT_QOS="${MG_AGENT_MQTT_QOS:-0}"
MG_AGENT_MQTT_RETAIN="${MG_AGENT_MQTT_RETAIN:-false}"
MG_AGENT_MQTT_CA_PATH="${MG_AGENT_MQTT_CA_PATH:-ca.crt}"
MG_AGENT_MQTT_CERT_PATH="${MG_AGENT_MQTT_CERT_PATH:-client.cert}"
MG_AGENT_MQTT_PRIV_KEY_PATH="${MG_AGENT_MQTT_PRIV_KEY_PATH:-client.key}"
MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID:-my-device-001}"
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY:-my-device-secret}"
MG_AGENT_BOOTSTRAP_CLIENT_CERT="${MG_AGENT_BOOTSTRAP_CLIENT_CERT:-}"
MG_AGENT_BOOTSTRAP_CLIENT_KEY="${MG_AGENT_BOOTSTRAP_CLIENT_KEY:-}"
MG_AGENT_BOOTSTRAP_CA_CERT="${MG_AGENT_BOOTSTRAP_CA_CERT:-}"
MG_AGENT_PORT="${MG_AGENT_PORT:-9999}"
MG_AGENT_BROKER_URL="${MG_AGENT_BROKER_URL:-amqp://guest:guest@fluxmq:5682/}"
MG_AGENT_NODERED_URL="${MG_AGENT_NODERED_URL:-http://nodered:1880/}"
MG_AGENT_HEARTBEAT_INTERVAL="${MG_AGENT_HEARTBEAT_INTERVAL:-10s}"
MG_AGENT_TERMINAL_SESSION_TIMEOUT="${MG_AGENT_TERMINAL_SESSION_TIMEOUT:-1m0s}"
MG_AGENT_LOG_LEVEL="${MG_AGENT_LOG_LEVEL:-info}"
MG_RULES_RETRIES="${MG_RULES_RETRIES:-5}"
MG_RULES_RETRY_DELAY_SECONDS="${MG_RULES_RETRY_DELAY_SECONDS:-2}"

DOMAIN_ID="${MG_DOMAIN_ID:-}"

if [ -z "$DOMAIN_ID" ]; then
  echo "ERROR: MG_DOMAIN_ID is required."
  exit 1
fi

if [ -z "${MG_PAT:-}" ]; then
  echo "ERROR: MG_PAT is required."
  exit 1
fi

# Optional: Build DOMAIN_API for informational purposes (only if MG_API is set)
if [ -n "${MG_API:-}" ]; then
  DOMAIN_API="${MG_API}/${DOMAIN_ID}"
fi

echo "=== Magistrala Mock Device Provisioning ==="
echo "Clients API:  ${MG_CLIENTS_API}"
echo "Channels API: ${MG_CHANNELS_API}"
echo "Rules API:    ${MG_RULES_API}"
echo "Bootstrap API: ${MG_BOOTSTRAP_API}"
echo "Domain ID:    ${DOMAIN_ID}"
echo ""

TOKEN="${MG_PAT}"
if [ -z "$TOKEN" ]; then
  echo "ERROR: MG_PAT environment variable is not set."
  exit 1
fi
echo "Step 1: Using PAT token (${#TOKEN} characters)."
echo "Token starts with: ${TOKEN:0:30}"
echo "Token ends with: ${TOKEN: -20}"

json_bool() {
  case "${1,,}" in
    1|true|yes|on) echo "true" ;;
    *) echo "false" ;;
  esac
}

build_bootstrap_content() {
  DOMAIN_ID="${DOMAIN_ID}" \
  CHANNEL="${CHANNEL}" \
  MG_AGENT_BROKER_URL="${MG_AGENT_BROKER_URL}" \
  MG_AGENT_PORT="${MG_AGENT_PORT}" \
  MG_AGENT_NODERED_URL="${MG_AGENT_NODERED_URL}" \
  MG_AGENT_LOG_LEVEL="${MG_AGENT_LOG_LEVEL}" \
  MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL}" \
  MG_AGENT_MQTT_MTLS="$(json_bool "${MG_AGENT_MQTT_MTLS}")" \
  MG_AGENT_MQTT_SKIP_TLS="$(json_bool "${MG_AGENT_MQTT_SKIP_TLS}")" \
  MG_AGENT_MQTT_QOS="${MG_AGENT_MQTT_QOS}" \
  MG_AGENT_MQTT_RETAIN="$(json_bool "${MG_AGENT_MQTT_RETAIN}")" \
  MG_AGENT_MQTT_CA_PATH="${MG_AGENT_MQTT_CA_PATH}" \
  MG_AGENT_MQTT_CERT_PATH="${MG_AGENT_MQTT_CERT_PATH}" \
  MG_AGENT_MQTT_PRIV_KEY_PATH="${MG_AGENT_MQTT_PRIV_KEY_PATH}" \
  MG_AGENT_HEARTBEAT_INTERVAL="${MG_AGENT_HEARTBEAT_INTERVAL}" \
  MG_AGENT_TERMINAL_SESSION_TIMEOUT="${MG_AGENT_TERMINAL_SESSION_TIMEOUT}" \
  python3 - <<'PY'
import json
import os

def parse_bool(value):
    return str(value).lower() in {"1", "true", "yes", "on"}

content = {
    "agent": {
        "domain_id": os.environ["DOMAIN_ID"],
        "channels": {
            "id": os.environ["CHANNEL"],
        },
        "server": {
            "broker_url": os.environ["MG_AGENT_BROKER_URL"],
            "port": os.environ["MG_AGENT_PORT"],
        },
        "nodered": {
            "url": os.environ["MG_AGENT_NODERED_URL"],
        },
        "log": {
            "level": os.environ["MG_AGENT_LOG_LEVEL"],
        },
        "mqtt": {
            "url": os.environ["MG_AGENT_MQTT_URL"],
            "mtls": parse_bool(os.environ["MG_AGENT_MQTT_MTLS"]),
            "skip_tls_ver": parse_bool(os.environ["MG_AGENT_MQTT_SKIP_TLS"]),
            "qos": int(os.environ["MG_AGENT_MQTT_QOS"]),
            "retain": parse_bool(os.environ["MG_AGENT_MQTT_RETAIN"]),
            "ca_path": os.environ["MG_AGENT_MQTT_CA_PATH"],
            "cert_path": os.environ["MG_AGENT_MQTT_CERT_PATH"],
            "priv_key_path": os.environ["MG_AGENT_MQTT_PRIV_KEY_PATH"],
        },
        "heartbeat": {
            "interval": os.environ["MG_AGENT_HEARTBEAT_INTERVAL"],
        },
        "terminal": {
            "session_timeout": os.environ["MG_AGENT_TERMINAL_SESSION_TIMEOUT"],
        },
    }
}
print(json.dumps(content, separators=(",", ":")))
PY
}

build_bootstrap_payload() {
  CLIENT_ID="${CLIENT_ID}" \
  CHANNEL="${CHANNEL}" \
  MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}" \
  MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}" \
  MG_AGENT_BOOTSTRAP_CLIENT_CERT="${MG_AGENT_BOOTSTRAP_CLIENT_CERT}" \
  MG_AGENT_BOOTSTRAP_CLIENT_KEY="${MG_AGENT_BOOTSTRAP_CLIENT_KEY}" \
  MG_AGENT_BOOTSTRAP_CA_CERT="${MG_AGENT_BOOTSTRAP_CA_CERT}" \
  BOOTSTRAP_CONTENT="${BOOTSTRAP_CONTENT}" \
  python3 - <<'PY'
import json
import os

payload = {
    "client_id": os.environ["CLIENT_ID"],
    "external_id": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_ID"],
    "external_key": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_KEY"],
    "name": "agent-mock-device-config",
    "channels": [os.environ["CHANNEL"]],
    "content": os.environ["BOOTSTRAP_CONTENT"],
    "client_cert": os.environ["MG_AGENT_BOOTSTRAP_CLIENT_CERT"],
    "client_key": os.environ["MG_AGENT_BOOTSTRAP_CLIENT_KEY"],
    "ca_cert": os.environ["MG_AGENT_BOOTSTRAP_CA_CERT"],
    "state": 1,
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

post_json() {
  local url="$1"
  local payload="$2"

  curl -sSL -X POST "${url}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -w "\n%{http_code}" \
    -d "${payload}"
}

response_code() {
  printf '%s\n' "$1" | tail -n1
}

response_body() {
  printf '%s\n' "$1" | sed '$d'
}

require_created() {
  local step="$1"
  local url="$2"
  local response="$3"
  local code
  local body

  code=$(response_code "${response}")
  body=$(response_body "${response}")

  if [ "${code}" != "200" ] && [ "${code}" != "201" ]; then
    echo "ERROR: ${step} returned HTTP ${code}."
    echo "Endpoint: ${url}"
    echo "Response: ${body}"
    exit 1
  fi
}

require_created_with_retry() {
  local step="$1"
  local url="$2"
  local payload="$3"
  local retries="$4"
  local delay="$5"
  local response
  local code
  local body
  local attempt=1

  while [ "${attempt}" -le "${retries}" ]; do
    response=$(post_json "${url}" "${payload}")
    code=$(response_code "${response}")
    body=$(response_body "${response}")

    if [ "${code}" = "200" ] || [ "${code}" = "201" ]; then
      printf '%s\n' "${response}"
      return 0
    fi

    if [ "${attempt}" -lt "${retries}" ]; then
      echo "  Attempt ${attempt}/${retries} failed with HTTP ${code}; retrying in ${delay}s..."
      sleep "${delay}"
    fi
    attempt=$((attempt + 1))
  done

  echo "ERROR: ${step} returned HTTP ${code}."
  echo "Endpoint: ${url}"
  echo "Response: ${body}"
  exit 1
}

# Step 2: Create the agent Client (device)
echo ""
echo "Step 2: Creating agent Client (device)..."
CLIENT_URL="${MG_CLIENTS_API}/${DOMAIN_ID}/clients"
echo "  API: ${CLIENT_URL}"
echo "  Token: ${TOKEN:0:20}..." # Show first 20 chars only

CLIENT_PAYLOAD="{
  \"name\": \"agent-mock-device\",
  \"metadata\": {
    \"type\": \"agent\",
    \"description\": \"Mock IoT gateway device running Magistrala Agent with Node-RED\"
  },
  \"status\": \"enabled\"
}"
CLIENT_RESPONSE=$(post_json "${CLIENT_URL}" "${CLIENT_PAYLOAD}")
require_created "Client creation" "${CLIENT_URL}" "${CLIENT_RESPONSE}"
CLIENT_BODY=$(response_body "${CLIENT_RESPONSE}")

CLIENT_ID=$(echo "$CLIENT_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
CLIENT_SECRET=$(echo "$CLIENT_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credentials',{}).get('secret',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create Client."
  echo "Endpoint: ${CLIENT_URL}"
  echo "Response: ${CLIENT_BODY}"
  echo ""
  echo "Troubleshooting:"
  echo "  1. Verify MG_PAT token is valid: export MG_PAT='<your-token>'"
  echo "  2. Verify DOMAIN_ID is correct: export MG_DOMAIN_ID='<domain-id>'"
  echo "  3. Check that clients API is running: ${CLIENT_URL}"
  echo "  4. Try the same request in Postman to verify it works"
  exit 1
fi
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"

# Step 3: Create Channel
echo ""
echo "Step 3: Creating Channel..."
CHANNEL_URL="${MG_CHANNELS_API}/${DOMAIN_ID}/channels"
echo "  API: ${CHANNEL_URL}"
CHANNEL_PAYLOAD="{
  \"name\": \"agent-channel\",
  \"description\": \"Agent channel for data and control\",
  \"metadata\": {
    \"type\": \"agent\"
  },
  \"status\": \"enabled\"
}"
CH_RESPONSE=$(post_json "${CHANNEL_URL}" "${CHANNEL_PAYLOAD}")
require_created "Channel creation" "${CHANNEL_URL}" "${CH_RESPONSE}"
CH_BODY=$(response_body "${CH_RESPONSE}")

CHANNEL=$(echo "$CH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$CHANNEL" ]; then
  echo "ERROR: Failed to create Channel."
  echo "Endpoint: ${CHANNEL_URL}"
  echo "Response: ${CH_BODY}"
  exit 1
fi
echo "  Channel: ${CHANNEL}"

# Step 4: Create Bootstrap configuration
echo ""
echo "Step 4: Creating Bootstrap configuration..."
BOOTSTRAP_CONTENT=$(build_bootstrap_content)
BOOTSTRAP_PAYLOAD=$(build_bootstrap_payload)
BOOT_CONFIG_URL="${MG_BOOTSTRAP_API}/${DOMAIN_ID}/clients/configs"
echo "  API: ${BOOT_CONFIG_URL}"
BOOT_RESPONSE=$(post_json "${BOOT_CONFIG_URL}" "${BOOTSTRAP_PAYLOAD}")
require_created "Bootstrap configuration" "${BOOT_CONFIG_URL}" "${BOOT_RESPONSE}"
echo "  Bootstrap configuration created."

# Step 5: Set up Rule Engine to store messages as SenML
echo ""
echo "Step 5: Configuring Rule Engine (save_senml) for 'data' subtopic..."
RULE_CONFIG_URL="${MG_RULES_API}/${DOMAIN_ID}/rules"
echo "  API: ${RULE_CONFIG_URL}"
RULE_PAYLOAD="{
  \"name\": \"agent-mock-device-storage-data\",
  \"domain\": \"${DOMAIN_ID}\",
  \"input_channel\": \"${CHANNEL}\",
  \"input_topic\": \"data\",
  \"logic\": {
    \"type\": 0,
    \"value\": \"return message.payload\"
  },
  \"outputs\": [
    {\"type\": \"save_senml\"}
  ],
  \"status\": \"enabled\"
}"
RE_RESPONSE=$(require_created_with_retry \
  "Rule Engine configuration for 'data' subtopic" \
  "${RULE_CONFIG_URL}" \
  "${RULE_PAYLOAD}" \
  "${MG_RULES_RETRIES}" \
  "${MG_RULES_RETRY_DELAY_SECONDS}")
echo "  Rule Engine configured for 'data' subtopic (save_senml)."

# Step 6: Update configs/config.toml with provisioned values
echo ""
echo "Step 6: Updating configs/config.toml..."
CONFIG_FILE="configs/config.toml"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "ERROR: $CONFIG_FILE not found. Run from the project root or ensure configs/config.toml exists."
  exit 1
fi

# Create a temporary TOML file with updated values
cat > "${CONFIG_FILE}.tmp" << EOF
File = "/config.toml"
domain_id = "${DOMAIN_ID}"

[channels]
  id = "${CHANNEL}"

[heartbeat]
  interval = "${MG_AGENT_HEARTBEAT_INTERVAL}"

[log]
  level = "${MG_AGENT_LOG_LEVEL}"

[mqtt]
  ca_cert = ""
  ca_path = "${MG_AGENT_MQTT_CA_PATH}"
  cert_path = "${MG_AGENT_MQTT_CERT_PATH}"
  client_cert = ""
  client_key = ""
  mtls = ${MG_AGENT_MQTT_MTLS}
  password = "${CLIENT_SECRET}"
  priv_key_path = "${MG_AGENT_MQTT_PRIV_KEY_PATH}"
  qos = ${MG_AGENT_MQTT_QOS}
  retain = ${MG_AGENT_MQTT_RETAIN}
  skip_tls_ver = ${MG_AGENT_MQTT_SKIP_TLS}
  url = "${MG_AGENT_MQTT_URL}"
  username = "${CLIENT_ID}"

[nodered]
  url = "${MG_AGENT_NODERED_URL}"

[server]
  broker_url = "${MG_AGENT_BROKER_URL}"
  port = "${MG_AGENT_PORT}"

[terminal]
  session_timeout = "${MG_AGENT_TERMINAL_SESSION_TIMEOUT}"
EOF

mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
echo "  configs/config.toml updated."

# Summary
echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Resources created:"
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"
echo "  Channel ID:    ${CHANNEL}"
echo "  Domain ID:     ${DOMAIN_ID}"
echo "  Bootstrap ID:  ${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}"
echo "  Bootstrap Key: ${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}"
echo "  Storage rule:  data"
echo ""
echo "Configuration saved to: configs/config.toml"
echo ""
echo "=== Next Steps ==="
echo ""
echo "Option 1: Direct Execution (uses config.toml)"
echo "  1. Run:  make run"
echo "  2. Open: http://localhost:1880  (Node-RED UI)"
echo "  3. Agent uses credentials from configs/config.toml"
echo ""
echo "Option 2: Bootstrap Mode (recommended for cloud/remote)"
echo "  1. Set environment variables:"
echo "     export MG_AGENT_BOOTSTRAP_ID=${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}"
echo "     export MG_AGENT_BOOTSTRAP_KEY=${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}"
echo "     export MG_AGENT_BOOTSTRAP_URL=${MG_BOOTSTRAP_API}/clients/bootstrap"
echo "  2. Run:  make run"
echo "  3. Agent fetches config from bootstrap service"
echo ""
echo "=== MQTT Connection Details ==="
echo "  Username: ${CLIENT_ID}"
echo "  Password: ${CLIENT_SECRET}"
echo "  Channel:  ${CHANNEL}"
echo "  Domain:   ${DOMAIN_ID}"
echo ""
echo "=== Test MQTT Publishing ==="
echo ""
echo "Local (localhost:8883):"
echo "  mosquitto_pub -I \"agent-mock-device\" \\"
echo "    -u ${CLIENT_ID} \\"
echo "    -P ${CLIENT_SECRET} \\"
echo "    -t m/${DOMAIN_ID}/c/${CHANNEL}/data \\"
echo "    -h localhost -p 8883 \\"
echo "    -m '[{\"n\":\"Temperature\",\"bu\":\"°C\",\"u\":\"°C\",\"v\":30}]' \\"
echo "    --cafile docker/ssl/certs/ca.crt"
echo ""
echo "Cloud (messaging.magistrala.absmach.eu:8883):"
echo "  mosquitto_pub -I \"agent-mock-device\" \\"
echo "    -h messaging.magistrala.absmach.eu -p 8883 \\"
echo "    --capath /etc/ssl/certs \\"
echo "    -u ${CLIENT_ID} \\"
echo "    -P ${CLIENT_SECRET} \\"
echo "    -t m/${DOMAIN_ID}/c/${CHANNEL}/data \\"
echo "    -m '[{\"n\":\"Temperature\",\"bu\":\"°C\",\"u\":\"°C\",\"v\":30}]'"
echo ""
echo "=== Deploy Node-RED Flow ==="
echo "  FLOWS=\$(cat examples/nodered/speed-flow.json | base64 -w 0)"
echo "  curl -s -X POST http://localhost:9999/nodered \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d \"{\\\"command\\\":\\\"nodered-deploy\\\",\\\"flows\\\":\\\"\$FLOWS\\\"}\""
