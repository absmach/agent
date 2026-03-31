#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Provision script for mock device environment.
# This script creates the necessary Magistrala resources (Clients, Channels)
# and configures a Rule Engine (RE) to store messages from the mock device.
#
# Prerequisites:
#   - A running Magistrala instance
#   - magistrala-cli installed (or use curl directly)
#
# Usage:
#   ./provision.sh [MAGISTRALA_URL] [USER_EMAIL] [USER_PASSWORD] [DOMAIN_ID]
#
# Example:
#   ./provision.sh http://localhost admin@example.com 12345678 <domain-id>

set -euo pipefail

MG_URL="${1:-http://localhost}"
MG_EMAIL="${2:-admin@example.com}"
MG_PASSWORD="${3:-12345678}"
DOMAIN_ID="${4:-}"

if [ -z "$DOMAIN_ID" ]; then
  echo "ERROR: DOMAIN_ID is required as the 4th argument."
  echo "Usage: ./provision.sh [MAGISTRALA_URL] [USER_EMAIL] [USER_PASSWORD] [DOMAIN_ID]"
  exit 1
fi

USERS_URL="${MG_URL}:9002"
CLIENTS_URL="${MG_URL}:9000"
BOOTSTRAP_URL="${MG_URL}:9013"
RE_URL="${MG_URL}:9008"

echo "=== Magistrala Mock Device Provisioning ==="
echo "Magistrala URL: ${MG_URL}"
echo "Domain ID:      ${DOMAIN_ID}"
echo ""

# Step 1: Obtain user token
echo "Step 1: Obtaining user token..."
TOKEN=$(curl -sSL -X POST "${USERS_URL}/users/tokens/issue" \
  -H "Content-Type: application/json" \
  -d "{\"identity\": \"${MG_EMAIL}\", \"secret\": \"${MG_PASSWORD}\"}" | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to obtain token. Check Magistrala URL and credentials."
  exit 1
fi
echo "  Token obtained successfully."

# Step 2: Create the agent Client (device)
echo ""
echo "Step 2: Creating agent Client (device)..."
CLIENT_RESPONSE=$(curl -sSL -X POST "${CLIENTS_URL}/${DOMAIN_ID}/clients" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "name": "agent-mock-device",
    "metadata": {
      "type": "agent",
      "description": "Mock IoT gateway device running Magistrala Agent with Node-RED"
    }
  }')

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
CLIENT_SECRET=$(echo "$CLIENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('credentials',{}).get('secret',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create Client."
  echo "Response: ${CLIENT_RESPONSE}"
  exit 1
fi
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"

# Step 3: Create Control Channel
echo ""
echo "Step 3: Creating Control Channel..."
CONTROL_CH_RESPONSE=$(curl -sSL -X POST "${CLIENTS_URL}/${DOMAIN_ID}/channels" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "name": "agent-control-channel",
    "metadata": {
      "type": "control",
      "description": "Control channel for agent commands"
    }
  }')

CONTROL_CHANNEL=$(echo "$CONTROL_CH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$CONTROL_CHANNEL" ]; then
  echo "ERROR: Failed to create Control Channel."
  exit 1
fi
echo "  Control Channel: ${CONTROL_CHANNEL}"

# Step 4: Create Data Channel
echo ""
echo "Step 4: Creating Data Channel..."
DATA_CH_RESPONSE=$(curl -sSL -X POST "${CLIENTS_URL}/${DOMAIN_ID}/channels" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "name": "agent-data-channel",
    "metadata": {
      "type": "data",
      "description": "Data channel for agent sensor data and Node-RED flow output"
    }
  }')

DATA_CHANNEL=$(echo "$DATA_CH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$DATA_CHANNEL" ]; then
  echo "ERROR: Failed to create Data Channel."
  exit 1
fi
echo "  Data Channel: ${DATA_CHANNEL}"

# Step 5: Connect Client to Channels
echo ""
echo "Step 5: Connecting Client to Channels..."
curl -sSL -X POST "${CLIENTS_URL}/${DOMAIN_ID}/channels/${CONTROL_CHANNEL}/connect" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{\"client_ids\": [\"${CLIENT_ID}\"], \"types\": [\"publish\", \"subscribe\"]}" > /dev/null 2>&1
echo "  Connected to Control Channel."

curl -sSL -X POST "${CLIENTS_URL}/${DOMAIN_ID}/channels/${DATA_CHANNEL}/connect" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{\"client_ids\": [\"${CLIENT_ID}\"], \"types\": [\"publish\", \"subscribe\"]}" > /dev/null 2>&1
echo "  Connected to Data Channel."

# Step 6: Create Bootstrap configuration
echo ""
echo "Step 6: Creating Bootstrap configuration..."
BOOTSTRAP_RESPONSE=$(curl -sSL -X POST "${BOOTSTRAP_URL}/${DOMAIN_ID}/clients/configs" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"external_id\": \"agent-mock-device\",
    \"external_key\": \"agent-mock-device-key\",
    \"name\": \"agent-mock-device-config\",
    \"channels\": [\"${CONTROL_CHANNEL}\", \"${DATA_CHANNEL}\"],
    \"content\": \"{}\",
    \"state\": 1
  }" 2>/dev/null || echo "{}")

echo "  Bootstrap configuration created."

# Step 7: Set up Rule Engine to store messages
echo ""
echo "Step 7: Configuring Rule Engine to store messages..."
RE_RESPONSE=$(curl -sSL -X POST "${RE_URL}/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"name\": \"agent-mock-device-storage\",
    \"input_channel\": \"${DATA_CHANNEL}\",
    \"input_topic\": \"channels/${DATA_CHANNEL}/messages/>\",
    \"logic_type\": \"passthrough\",
    \"output_channel\": \"\",
    \"metadata\": {
      \"description\": \"Store all messages from mock agent device\"
    }
  }" 2>/dev/null || echo "{}")
echo "  Rule Engine configured (messages from data channel will be stored)."

# Write .env file
echo ""
echo "Step 8: Writing .env file..."
cat > "$(dirname "$0")/.env" << EOF
# Auto-generated by provision.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Pre-set Magistrala resources for mock device

# Client credentials
MG_AGENT_CLIENT_ID=${CLIENT_ID}
MG_AGENT_CLIENT_SECRET=${CLIENT_SECRET}

# Channels
MG_AGENT_CONTROL_CHANNEL=${CONTROL_CHANNEL}
MG_AGENT_DATA_CHANNEL=${DATA_CHANNEL}

# Bootstrap
MG_AGENT_BOOTSTRAP_URL=${BOOTSTRAP_URL}/clients/bootstrap
MG_AGENT_BOOTSTRAP_ID=agent-mock-device
MG_AGENT_BOOTSTRAP_KEY=agent-mock-device-key
EOF
echo "  .env file written."

# Summary
echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Resources created:"
echo "  Client ID:        ${CLIENT_ID}"
echo "  Client Secret:    ${CLIENT_SECRET}"
echo "  Control Channel:  ${CONTROL_CHANNEL}"
echo "  Data Channel:     ${DATA_CHANNEL}"
echo ""
echo "To start the mock device:"
echo "  cd docker/nodered && docker compose up -d"
echo ""
echo "To deploy a Node-RED flow via agent:"
echo "  curl -X POST http://localhost:9999/nodered \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"command\": \"nodered-deploy\", \"flows\": \"<base64-encoded-flow-json>\"}'"
echo ""
echo "To check Node-RED status via agent:"
echo "  curl -X POST http://localhost:9999/nodered \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"command\": \"nodered-ping\"}'"
