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
#   MG_API       - API base URL (default: https://cloud.magistrala.absmach.eu/api)
#   MG_DOMAIN_ID - Domain ID (required)
#   MG_PAT       - Personal Access Token (required)
#
# Usage:
#   export MG_PAT=pat_xxx
#   export MG_DOMAIN_ID=<domain-id>
#   ./provision.sh
#
# Optionally override the API URL:
#   MG_API=https://my-instance/api ./provision.sh

set -euo pipefail

MG_API="${MG_API:-https://cloud.magistrala.absmach.eu/api}"
DOMAIN_ID="${MG_DOMAIN_ID:-}"

if [ -z "$DOMAIN_ID" ]; then
  echo "ERROR: MG_DOMAIN_ID is required."
  exit 1
fi

if [ -z "${MG_PAT:-}" ]; then
  echo "ERROR: MG_PAT is required."
  exit 1
fi

DOMAIN_API="${MG_API}/${DOMAIN_ID}"

echo "=== Magistrala Mock Device Provisioning ==="
echo "API URL:   ${MG_API}"
echo "Domain ID: ${DOMAIN_ID}"
echo ""

TOKEN="${MG_PAT}"
echo "Step 1: Using PAT token."

# Step 2: Create the agent Client (device)
echo ""
echo "Step 2: Creating agent Client (device)..."
CLIENT_RESPONSE=$(curl -sSL -X POST "${DOMAIN_API}/clients" \
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

# Step 3: Create Channel
echo ""
echo "Step 3: Creating Channel..."
CH_RESPONSE=$(curl -sSL -X POST "${DOMAIN_API}/channels" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "name": "agent-channel",
    "metadata": {
      "description": "Agent channel (req/data/res subtopics)"
    }
  }')

CHANNEL=$(echo "$CH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$CHANNEL" ]; then
  echo "ERROR: Failed to create Channel."
  exit 1
fi
echo "  Channel: ${CHANNEL}"

# Step 4: Connect Client to Channel
echo ""
echo "Step 4: Connecting Client to Channel..."
curl -sSL -X POST "${DOMAIN_API}/channels/${CHANNEL}/connect" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{\"client_ids\": [\"${CLIENT_ID}\"], \"types\": [\"publish\", \"subscribe\"]}" > /dev/null 2>&1
echo "  Connected."

# Step 5: Create Bootstrap configuration
echo ""
echo "Step 5: Creating Bootstrap configuration..."
curl -sSL -X POST "${DOMAIN_API}/clients/configs" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"external_id\": \"agent-mock-device\",
    \"external_key\": \"agent-mock-device-key\",
    \"name\": \"agent-mock-device-config\",
    \"channels\": [\"${CHANNEL}\"],
    \"content\": \"{}\",
    \"state\": 1
  }" > /dev/null 2>&1
echo "  Bootstrap configuration created."

# Step 6: Set up Rule Engine to store messages as SenML
echo ""
echo "Step 6: Configuring Rule Engine (save_senml)..."
RE_RESPONSE=$(curl -sSL -o /dev/null -w "%{http_code}" -X POST "${DOMAIN_API}/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"name\": \"agent-mock-device-storage\",
    \"input_channel\": \"${CHANNEL}\",
    \"input_topic\": \">\",
    \"logic\": {
      \"type\": 0,
      \"value\": \"return true\"
    },
    \"outputs\": [
      {\"type\": \"save_senml\"}
    ],
    \"metadata\": {
      \"description\": \"Save all SenML messages from mock agent device\"
    }
  }" 2>/dev/null || echo "000")
if [ "$RE_RESPONSE" = "201" ] || [ "$RE_RESPONSE" = "200" ]; then
  echo "  Rule Engine configured (save_senml)."
else
  echo "  WARNING: Rule Engine returned HTTP ${RE_RESPONSE}. Check manually if needed."
fi

# Step 6b: Modbus alarm rule — triggers on out-of-range holding register values
echo ""
echo "Step 6b: Configuring Modbus alarm rule..."
MODBUS_LUA='for _, m in ipairs(message.payload) do
  if m.n and string.match(m.n, "^hr%d") then
    if m.v and (m.v < 0 or m.v > 32767) then
      return {cause="modbus_out_of_range", register=m.n, value=m.v, severity=70}
    end
  end
end
return false'

MODBUS_RE_RESPONSE=$(curl -sSL -o /dev/null -w "%{http_code}" -X POST "${DOMAIN_API}/rules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "{
    \"name\": \"modbus-register-alarm\",
    \"input_channel\": \"${CHANNEL}\",
    \"input_topic\": \">\",
    \"logic\": {
      \"type\": 0,
      \"value\": $(python3 -c "import json,sys; print(json.dumps(open('/dev/stdin').read()))" <<< "$MODBUS_LUA")
    },
    \"outputs\": [
      {\"type\": \"alarms\"},
      {\"type\": \"save_senml\"}
    ],
    \"metadata\": {
      \"description\": \"Alarm on Modbus holding register out-of-range values\"
    }
  }" 2>/dev/null || echo "000")
if [ "$MODBUS_RE_RESPONSE" = "201" ] || [ "$MODBUS_RE_RESPONSE" = "200" ]; then
  echo "  Modbus alarm rule created."
else
  echo "  WARNING: Modbus rule returned HTTP ${MODBUS_RE_RESPONSE}. Check manually if needed."
fi

# Step 7: Update docker/.env with provisioned values
echo ""
echo "Step 7: Updating docker/.env..."
ENV_FILE="$(dirname "$0")/../.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run from the project root or ensure docker/.env exists."
  exit 1
fi

update_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

update_env "MG_AGENT_CLIENT_ID"     "${CLIENT_ID}"
update_env "MG_AGENT_CLIENT_SECRET" "${CLIENT_SECRET}"
update_env "MG_AGENT_DOMAIN_ID"     "${DOMAIN_ID}"
update_env "MG_AGENT_CHANNEL"       "${CHANNEL}"

echo "  docker/.env updated."

# Summary
echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Resources created:"
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"
echo "  Channel:       ${CHANNEL}"
echo ""
echo "Next steps:"
echo "  1. Run:  make run"
echo "  2. Open: http://localhost:1880  (Node-RED UI)"
echo ""
echo "Deploy a Node-RED flow via HTTP:"
echo "  FLOWS=\$(cat examples/nodered/speed-flow.json | base64 -w 0)"
echo "  curl -s -X POST http://localhost:9999/nodered \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d \"{\\\"command\\\":\\\"nodered-deploy\\\",\\\"flows\\\":\\\"\$FLOWS\\\"}\""


