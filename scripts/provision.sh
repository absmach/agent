#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Provision script for mock device environment.
# This script creates the necessary Magistrala resources (Client, Channel,
# Bootstrap Profile, Bootstrap Enrollment) and configures a Rule Engine to
# store messages from the mock device.
#
# Bootstrap flow (new profile-based API):
#   Step 4a - Create a Bootstrap Profile with a Go template and binding slots
#   Step 4b - Create a Bootstrap Enrollment linked to the profile
#   Step 4c - Bind the device client and channel to the enrollment slots
#
# Prerequisites:
#   - A running Magistrala instance (self-hosted or cloud)
#   - curl and python3 available
#
# Environment variables:
#   MG_API           - Base API URL for all services (e.g., https://cloud.magistrala.absmach.eu/api)
#                      If set, overrides individual service API settings
#   MG_CLIENTS_API   - Clients service API base URL (default: http://localhost:9006)
#   MG_CHANNELS_API  - Channels service API base URL (default: http://localhost:9005)
#   MG_RULES_API     - Rules service API base URL (default: http://localhost:9008)
#   MG_BOOTSTRAP_API - Bootstrap service API base URL (default: http://localhost:9013)
#   MG_DOMAIN_ID     - Domain ID (required)
#   MG_PAT           - Personal Access Token (required)
#   MG_AGENT_BOOTSTRAP_EXTERNAL_ID  - External bootstrap ID for the device
#   MG_AGENT_BOOTSTRAP_EXTERNAL_KEY - External bootstrap key for the device
#   MG_AGENT_BOOTSTRAP_CLIENT_CERT  - Optional PEM client certificate to store in bootstrap
#   MG_AGENT_BOOTSTRAP_CLIENT_KEY   - Optional PEM client key to store in bootstrap
#   MG_AGENT_BOOTSTRAP_CA_CERT      - Optional PEM CA certificate to store in bootstrap
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

set -euo pipefail

# Check if a unified API base URL is provided
if [ -n "${MG_API:-}" ]; then
  MG_CLIENTS_API="${MG_CLIENTS_API:-${MG_API}}"
  MG_CHANNELS_API="${MG_CHANNELS_API:-${MG_API}}"
  MG_RULES_API="${MG_RULES_API:-${MG_API}}"
  MG_BOOTSTRAP_API="${MG_BOOTSTRAP_API:-${MG_API}}"
  DEFAULT_MQTT_URL="ssl://messaging.magistrala.absmach.eu:8883"
  DEFAULT_MQTT_SKIP_TLS="false"
else
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

echo "=== Magistrala Mock Device Provisioning ==="
echo "Clients API:   ${MG_CLIENTS_API}"
echo "Channels API:  ${MG_CHANNELS_API}"
echo "Rules API:     ${MG_RULES_API}"
echo "Bootstrap API: ${MG_BOOTSTRAP_API}"
echo "Domain ID:     ${DOMAIN_ID}"
echo ""

TOKEN="${MG_PAT}"
echo "Step 1: Using PAT token (${#TOKEN} characters)."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

json_bool() {
  case "${1,,}" in
    1|true|yes|on) echo "true" ;;
    *) echo "false" ;;
  esac
}

# POST request; outputs body + newline + HTTP status code.
post_json() {
  local url="$1"
  local payload="$2"

  curl -sSL -X POST "${url}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -w "\n%{http_code}" \
    -d "${payload}"
}

# PUT request; outputs body + newline + HTTP status code.
put_json() {
  local url="$1"
  local payload="$2"

  curl -sSL -X PUT "${url}" \
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
  local code body

  code=$(response_code "${response}")
  body=$(response_body "${response}")

  if [ "${code}" != "200" ] && [ "${code}" != "201" ]; then
    echo "ERROR: ${step} returned HTTP ${code}."
    echo "Endpoint: ${url}"
    echo "Response: ${body}"
    exit 1
  fi
}

# Validate a 204 No Content response (used for bindings PUT).
require_no_content() {
  local step="$1"
  local url="$2"
  local response="$3"
  local code body

  code=$(response_code "${response}")

  if [ "${code}" != "204" ]; then
    body=$(response_body "${response}")
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
  local response code body attempt=1

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

# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

# Build the Bootstrap Profile JSON payload.
# The content_template is a Go template rendered server-side by the bootstrap
# service using binding snapshots (.Bindings) and per-enrollment variables
# (.Vars). It produces the full agent ServicesConfig JSON.
build_profile_payload() {
  python3 - <<'PY'
import json

template = """{
  "agent": {
    "domain_id": "{{.Device.DomainID}}",
    "channels": {
      "id": "{{.Bindings.mqtt_channel.Snapshot.id}}"
    },
    "server": {
      "broker_url": "{{.Vars.broker_url}}",
      "port": "{{.Vars.port}}"
    },
    "nodered": {
      "url": "{{.Vars.nodered_url}}"
    },
    "log": {
      "level": "{{.Vars.log_level}}"
    },
    "mqtt": {
      "url": "{{.Vars.mqtt_url}}",
      "username": "{{.Bindings.device_client.Snapshot.id}}",
      "password": "{{.Bindings.device_client.Secret.secret}}",
      "mtls": {{.Vars.mtls}},
      "skip_tls_ver": {{.Vars.skip_tls_ver}},
      "qos": {{.Vars.qos}},
      "retain": {{.Vars.retain}},
      "ca_path": "{{.Vars.ca_path}}",
      "cert_path": "{{.Vars.cert_path}}",
      "priv_key_path": "{{.Vars.priv_key_path}}"
    },
    "heartbeat": {
      "interval": "{{.Vars.heartbeat_interval}}"
    },
    "terminal": {
      "session_timeout": "{{.Vars.session_timeout}}"
    }
  }
}"""

payload = {
    "name": "agent-linux-device-profile",
    "description": "Bootstrap profile for Linux mock IoT gateway device running Magistrala Agent",
    "template_format": "json",
    "content_template": template,
    "binding_slots": [
        {
            "name": "device_client",
            "type": "client",
            "required": True,
        },
        {
            "name": "mqtt_channel",
            "type": "channel",
            "required": True,
        },
    ],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# Build the Bootstrap Enrollment JSON payload.
# render_context supplies the static per-device variables (.Vars.*) referenced
# in the profile template. Dynamic values (credentials, channel ID) come from
# bindings resolved in step 4c.
build_enrollment_payload() {
  PROFILE_ID="${PROFILE_ID}" \
  MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}" \
  MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}" \
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
  MG_AGENT_BOOTSTRAP_CLIENT_CERT="${MG_AGENT_BOOTSTRAP_CLIENT_CERT}" \
  MG_AGENT_BOOTSTRAP_CLIENT_KEY="${MG_AGENT_BOOTSTRAP_CLIENT_KEY}" \
  MG_AGENT_BOOTSTRAP_CA_CERT="${MG_AGENT_BOOTSTRAP_CA_CERT}" \
  python3 - <<'PY'
import json
import os

def parse_bool(value):
    return str(value).lower() in {"1", "true", "yes", "on"}

payload = {
    "external_id": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_ID"],
    "external_key": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_KEY"],
    "name": "agent-mock-device-config",
    "profile_id": os.environ["PROFILE_ID"],
    "status": "enabled",
    "render_context": {
        "broker_url":          os.environ["MG_AGENT_BROKER_URL"],
        "port":                os.environ["MG_AGENT_PORT"],
        "nodered_url":         os.environ["MG_AGENT_NODERED_URL"],
        "log_level":           os.environ["MG_AGENT_LOG_LEVEL"],
        "mqtt_url":            os.environ["MG_AGENT_MQTT_URL"],
        "mtls":                parse_bool(os.environ["MG_AGENT_MQTT_MTLS"]),
        "skip_tls_ver":        parse_bool(os.environ["MG_AGENT_MQTT_SKIP_TLS"]),
        "qos":                 int(os.environ["MG_AGENT_MQTT_QOS"]),
        "retain":              parse_bool(os.environ["MG_AGENT_MQTT_RETAIN"]),
        "ca_path":             os.environ["MG_AGENT_MQTT_CA_PATH"],
        "cert_path":           os.environ["MG_AGENT_MQTT_CERT_PATH"],
        "priv_key_path":       os.environ["MG_AGENT_MQTT_PRIV_KEY_PATH"],
        "heartbeat_interval":  os.environ["MG_AGENT_HEARTBEAT_INTERVAL"],
        "session_timeout":     os.environ["MG_AGENT_TERMINAL_SESSION_TIMEOUT"],
    },
    "client_cert": os.environ["MG_AGENT_BOOTSTRAP_CLIENT_CERT"],
    "client_key":  os.environ["MG_AGENT_BOOTSTRAP_CLIENT_KEY"],
    "ca_cert":     os.environ["MG_AGENT_BOOTSTRAP_CA_CERT"],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# Build the bindings payload that links profile slots to real resources.
build_bindings_payload() {
  CLIENT_ID="${CLIENT_ID}" \
  CHANNEL="${CHANNEL}" \
  python3 - <<'PY'
import json
import os

payload = {
    "bindings": [
        {
            "slot":        "device_client",
            "type":        "client",
            "resource_id": os.environ["CLIENT_ID"],
        },
        {
            "slot":        "mqtt_channel",
            "type":        "channel",
            "resource_id": os.environ["CHANNEL"],
        },
    ]
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# ---------------------------------------------------------------------------
# Step 2: Create the agent Client (device)
# ---------------------------------------------------------------------------
echo ""
echo "Step 2: Creating agent Client (device)..."
CLIENT_URL="${MG_CLIENTS_API}/${DOMAIN_ID}/clients"
echo "  API: ${CLIENT_URL}"

CLIENT_PAYLOAD='{
  "name": "agent-mock-device",
  "metadata": {
    "type": "agent",
    "description": "Mock IoT gateway device running Magistrala Agent with Node-RED"
  },
  "status": "enabled"
}'
CLIENT_RESPONSE=$(post_json "${CLIENT_URL}" "${CLIENT_PAYLOAD}")
require_created "Client creation" "${CLIENT_URL}" "${CLIENT_RESPONSE}"
CLIENT_BODY=$(response_body "${CLIENT_RESPONSE}")

CLIENT_ID=$(echo "$CLIENT_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
CLIENT_SECRET=$(echo "$CLIENT_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credentials',{}).get('secret',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create Client."
  echo "Endpoint: ${CLIENT_URL}"
  echo "Response: ${CLIENT_BODY}"
  exit 1
fi
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"

# ---------------------------------------------------------------------------
# Step 3: Create Channel
# ---------------------------------------------------------------------------
echo ""
echo "Step 3: Creating Channel..."
CHANNEL_URL="${MG_CHANNELS_API}/${DOMAIN_ID}/channels"
echo "  API: ${CHANNEL_URL}"

CHANNEL_PAYLOAD='{
  "name": "agent-channel",
  "description": "Agent channel for data and control",
  "metadata": {
    "type": "agent"
  },
  "status": "enabled"
}'
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
echo "  Channel ID: ${CHANNEL}"

# ---------------------------------------------------------------------------
# Step 4a: Create Bootstrap Profile
# ---------------------------------------------------------------------------
echo ""
echo "Step 4a: Creating Bootstrap Profile..."
PROFILE_URL="${MG_BOOTSTRAP_API}/${DOMAIN_ID}/clients/bootstrap/profiles"
echo "  API: ${PROFILE_URL}"

PROFILE_PAYLOAD=$(build_profile_payload)
PROFILE_RESPONSE=$(post_json "${PROFILE_URL}" "${PROFILE_PAYLOAD}")
require_created "Bootstrap Profile creation" "${PROFILE_URL}" "${PROFILE_RESPONSE}"
PROFILE_BODY=$(response_body "${PROFILE_RESPONSE}")

PROFILE_ID=$(echo "${PROFILE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [ -z "${PROFILE_ID}" ]; then
  echo "ERROR: Failed to extract Profile ID from response."
  echo "Response: ${PROFILE_BODY}"
  exit 1
fi
echo "  Profile ID: ${PROFILE_ID}"

# ---------------------------------------------------------------------------
# Step 4b: Create Bootstrap Enrollment
# The enrollment ID is returned in the Location response header.
# ---------------------------------------------------------------------------
echo ""
echo "Step 4b: Creating Bootstrap Enrollment..."
ENROLL_URL="${MG_BOOTSTRAP_API}/${DOMAIN_ID}/clients/configs"
echo "  API: ${ENROLL_URL}"

ENROLL_PAYLOAD=$(build_enrollment_payload)
ENROLL_HEADERS=$(mktemp)
ENROLL_RESPONSE=$(curl -sSL -X POST "${ENROLL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -D "${ENROLL_HEADERS}" \
  -w "\n%{http_code}" \
  -d "${ENROLL_PAYLOAD}")
require_created "Bootstrap Enrollment creation" "${ENROLL_URL}" "${ENROLL_RESPONSE}"

ENROLL_LOCATION=$(grep -i "^location:" "${ENROLL_HEADERS}" | tr -d '\r' | awk '{print $2}')
ENROLLMENT_ID=$(basename "${ENROLL_LOCATION}")
rm -f "${ENROLL_HEADERS}"

if [ -z "${ENROLLMENT_ID}" ]; then
  echo "ERROR: Failed to extract Enrollment ID from Location header."
  exit 1
fi
echo "  Enrollment ID: ${ENROLLMENT_ID}"

# ---------------------------------------------------------------------------
# Step 4c: Bind Resources
# Links device_client → CLIENT_ID and mqtt_channel → CHANNEL_ID so the
# profile template can render credentials and channel ID at bootstrap time.
# ---------------------------------------------------------------------------
echo ""
echo "Step 4c: Binding resources to enrollment..."
BINDINGS_URL="${MG_BOOTSTRAP_API}/${DOMAIN_ID}/clients/bootstrap/enrollments/${ENROLLMENT_ID}/bindings"
echo "  API: ${BINDINGS_URL}"

BINDINGS_PAYLOAD=$(build_bindings_payload)
BINDINGS_RESPONSE=$(put_json "${BINDINGS_URL}" "${BINDINGS_PAYLOAD}")
require_no_content "Bootstrap Bindings" "${BINDINGS_URL}" "${BINDINGS_RESPONSE}"
echo "  device_client → ${CLIENT_ID}"
echo "  mqtt_channel  → ${CHANNEL}"

# ---------------------------------------------------------------------------
# Step 5: Set up Rule Engine to store messages as SenML
# ---------------------------------------------------------------------------
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
require_created_with_retry \
  "Rule Engine configuration for 'data' subtopic" \
  "${RULE_CONFIG_URL}" \
  "${RULE_PAYLOAD}" \
  "${MG_RULES_RETRIES}" \
  "${MG_RULES_RETRY_DELAY_SECONDS}"
echo "  Rule Engine configured for 'data' subtopic (save_senml)."

# ---------------------------------------------------------------------------
# Step 6: Update configs/config.toml with provisioned values
# This supports direct (non-bootstrap) mode; bootstrap mode reads credentials
# from the rendered content field instead.
# ---------------------------------------------------------------------------
echo ""
echo "Step 6: Updating configs/config.toml..."
CONFIG_FILE="configs/config.toml"

mkdir -p configs

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

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Resources created:"
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"
echo "  Channel ID:    ${CHANNEL}"
echo "  Domain ID:     ${DOMAIN_ID}"
echo "  Profile ID:    ${PROFILE_ID}"
echo "  Enrollment ID: ${ENROLLMENT_ID}"
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
echo "  3. Agent fetches rendered config from bootstrap service"
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
