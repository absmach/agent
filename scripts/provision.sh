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
MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID:-my-device-001}"
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY:-my-device-secret}"

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

# Step 2: Create the agent Client (device)
echo ""
echo "Step 2: Creating agent Client (device)..."
echo "  API: ${MG_CLIENTS_API}/${DOMAIN_ID}/clients"
echo "  Token: ${TOKEN:0:20}..." # Show first 20 chars only

CLIENT_RESPONSE=$(curl -sSL -X POST "${MG_CLIENTS_API}/${DOMAIN_ID}/clients" \
  -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"${TOKEN}"'' \
  -d "{
    \"name\": \"agent-mock-device\",
    \"metadata\": {
      \"type\": \"agent\",
      \"description\": \"Mock IoT gateway device running Magistrala Agent with Node-RED\"
    },
    \"status\": \"enabled\"
  }")

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
CLIENT_SECRET=$(echo "$CLIENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credentials',{}).get('secret',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create Client."
  echo "Response: ${CLIENT_RESPONSE}"
  echo ""
  echo "Troubleshooting:"
  echo "  1. Verify MG_PAT token is valid: export MG_PAT='<your-token>'"
  echo "  2. Verify DOMAIN_ID is correct: export MG_DOMAIN_ID='<domain-id>'"
  echo "  3. Check that clients API is running: ${MG_CLIENTS_API}"
  echo "  4. Try the same request in Postman to verify it works"
  exit 1
fi
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"

# Step 3: Create Channel
echo ""
echo "Step 3: Creating Channel..."
CH_RESPONSE=$(curl -sSL -X POST "${MG_CHANNELS_API}/${DOMAIN_ID}/channels" \
  -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"${TOKEN}"'' \
  -d "{
    \"name\": \"agent-channel\",
    \"description\": \"Agent channel for data and control\",
    \"metadata\": {
      \"type\": \"agent\"
    },
    \"status\": \"enabled\"
  }")

CHANNEL=$(echo "$CH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$CHANNEL" ]; then
  echo "ERROR: Failed to create Channel."
  echo "Response: ${CH_RESPONSE}"
  exit 1
fi
echo "  Channel: ${CHANNEL}"

# Step 4: Connect Client to Channel
echo ""
echo "Step 4: Connecting Client to Channel..."
CONNECT_RESPONSE=$(curl -sSL -X POST "${MG_CHANNELS_API}/${DOMAIN_ID}/channels/connect" \
  -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"${TOKEN}"'' \
  -w "\n%{http_code}" \
  -d "{
    \"client_ids\": [\"${CLIENT_ID}\"],
    \"channel_ids\": [\"${CHANNEL}\"],
    \"types\": [\"publish\", \"subscribe\"]
  }")
CONNECT_HTTP_CODE=$(echo "$CONNECT_RESPONSE" | tail -n1)
CONNECT_BODY=$(echo "$CONNECT_RESPONSE" | sed '$d')

if [ "$CONNECT_HTTP_CODE" = "201" ] || [ "$CONNECT_HTTP_CODE" = "200" ]; then
  echo "  Connected successfully."
else
  echo "  WARNING: Connection returned HTTP ${CONNECT_HTTP_CODE}."
  echo "  Response: ${CONNECT_BODY}"
fi

# Step 5: Create Bootstrap configuration
echo ""
echo "Step 5: Creating Bootstrap configuration..."
BOOT_RESPONSE=$(curl -sSL -X POST "${MG_CLIENTS_API}/${DOMAIN_ID}/clients/configs" \
  -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"${TOKEN}"'' \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"external_id\": \"${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}\",
    \"external_key\": \"${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}\",
    \"name\": \"agent-mock-device-config\",
    \"channels\": [\"${CHANNEL}\"],
    \"content\": \"{}\",
    \"state\": 1
  }")
echo "  Bootstrap configuration created."

# Step 6: Set up Rule Engine to store messages as SenML
echo ""
echo "Step 6: Configuring Rule Engine (save_senml) for 'data' subtopic..."
RE_RESPONSE=$(curl -sSL -X POST "${MG_RULES_API}/${DOMAIN_ID}/rules" \
  -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"${TOKEN}"'' \
  -w "\n%{http_code}" \
  -d "{
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
  }")
RE_HTTP_CODE=$(echo "$RE_RESPONSE" | tail -n1)
RE_BODY=$(echo "$RE_RESPONSE" | sed '$d')
if [ "$RE_HTTP_CODE" = "201" ] || [ "$RE_HTTP_CODE" = "200" ]; then
  echo "  Rule Engine configured for 'data' subtopic (save_senml)."
else
  echo "  WARNING: Rule Engine returned HTTP ${RE_HTTP_CODE} for 'data' subtopic."
  echo "  Response: ${RE_BODY}"
fi

# Step 7: Update configs/config.toml with provisioned values
echo ""
echo "Step 7: Updating configs/config.toml..."
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
  interval = "10s"

[log]
  level = "info"

[mqtt]
  ca_cert = ""
  ca_path = "ca.crt"
  cert_path = "client.cert"
  client_cert = ""
  client_key = ""
  mtls = false
  password = "${CLIENT_SECRET}"
  priv_key_path = "client.key"
  qos = 0
  retain = false
  skip_tls_ver = ${MG_AGENT_MQTT_SKIP_TLS}
  url = "${MG_AGENT_MQTT_URL}"
  username = "${CLIENT_ID}"

[nodered]
  url = "http://nodered:1880/"

[server]
  broker_url = "amqp://guest:guest@fluxmq:5682/"
  port = "9999"

[terminal]
  session_timeout = "1m0s"
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
echo "     export MG_AGENT_BOOTSTRAP_URL=${MG_BOOTSTRAP_API}/${DOMAIN_ID}/clients/bootstrap"
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
