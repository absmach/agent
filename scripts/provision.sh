#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Provision script for mock device environment.
# This script creates the necessary Magistrala resources (Gateway, Channels,
# Bootstrap Profile, Bootstrap Enrollment) so that the agent can call the
# bootstrap endpoint at startup to receive its full configuration.
#
# Bootstrap flow (profile-based API):
#   Step 4a - Create a Bootstrap Profile with a Go template and binding slots
#   Step 4b - Create a Bootstrap Enrollment linked to the profile
#   Step 4c - Bind the device gateway and channels to the enrollment slots
#
# Prerequisites:
#   - A running Magistrala instance (self-hosted or cloud)
#   - curl and python3 available
#
# Environment variables:
#   MG_API           - Base API URL for all services (e.g., https://cloud.magistrala.absmach.eu/api)
#                      If set, overrides individual service API settings
#   MG_ATOM_API   - ATOM service API base URL (default: http://localhost:9006)
#   MG_RULES_API     - Rules service API base URL (default: http://localhost:9008)
#   MG_BOOTSTRAP_API - Bootstrap service API base URL (default: http://localhost:9013)
#   MG_PROVISION_API - Provision service API base URL (default: http://localhost:9016)
#                      Embedded in the bootstrap profile so the agent can register
#                      downstream devices without any extra env vars on the device.
#   MG_TENANT_ID     - Tenant ID (required)
#   MG_PAT           - Personal Access Token (required)
#   MG_AGENT_BOOTSTRAP_EXTERNAL_ID  - External bootstrap ID for the device (required)
#   MG_AGENT_BOOTSTRAP_EXTERNAL_KEY - External bootstrap key for the device (required)
#   MG_AGENT_BOOTSTRAP_GATEWAY_CERT  - Optional PEM gateway certificate to store in bootstrap
#   MG_AGENT_BOOTSTRAP_GATEWAY_KEY   - Optional PEM gateway key to store in bootstrap
#   MG_AGENT_BOOTSTRAP_CA_CERT      - Optional PEM CA certificate to store in bootstrap
#
# Usage (localhost):
#   export MG_PAT=pat_xxx
#   export MG_TENANT_ID=<tenant-id>
#   export MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<device-id>
#   export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<device-key>
#   ./provision.sh
#
# Usage (cloud):
#   export MG_API=https://cloud.magistrala.absmach.eu/api
#   export MG_PAT=pat_xxx
#   export MG_TENANT_ID=<tenant-id>
#   export MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<device-id>
#   export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<device-key>
#   ./provision.sh

set -euo pipefail

# Check if a unified API base URL is provided
if [ -n "${MG_API:-}" ]; then
    # Cloud / remote deployment: script API calls and agent-facing URLs are the same.
    MG_ATOM_API="${MG_ATOM_API:-${MG_API}}"
    MG_RULES_API="${MG_RULES_API:-${MG_API}}"
    MG_BOOTSTRAP_API="${MG_BOOTSTRAP_API:-${MG_API}}"
    MG_PROVISION_API="${MG_PROVISION_API:-${MG_API}}"
    # Agent-facing URLs default to the same remote base when MG_API is set.
    MG_AGENT_ATOM_URL="${MG_AGENT_ATOM_URL:-${MG_ATOM_API}}"
    MG_AGENT_RULES_URL="${MG_AGENT_RULES_URL:-${MG_RULES_API}}"
    DEFAULT_MQTT_URL="ssl://messaging.magistrala.absmach.eu:8883"
else
    # Local deployment: script runs on the host (localhost works), but the agent
    # runs inside Docker and uses the service-name aliases defined in extra_hosts.
    MG_ATOM_API="${MG_ATOM_API:-http://localhost:8080}"
    MG_RULES_API="${MG_RULES_API:-http://localhost:9008}"
    MG_BOOTSTRAP_API="${MG_BOOTSTRAP_API:-http://localhost:9013}"
    MG_PROVISION_API="${MG_PROVISION_API:-http://localhost:9016}"
    # Agent-facing URLs use Docker extra_hosts aliases so they resolve inside the container.
    MG_AGENT_ATOM_URL="${MG_AGENT_ATOM_URL:-http://atom:8080}"
    MG_AGENT_RULES_URL="${MG_AGENT_RULES_URL:-http://rules:9008}"
    DEFAULT_MQTT_URL="ssl://host.docker.internal:8883"
fi

MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL:-${DEFAULT_MQTT_URL}}"
MG_AGENT_BOOTSTRAP_GATEWAY_CERT="${MG_AGENT_BOOTSTRAP_GATEWAY_CERT:-}"
MG_AGENT_BOOTSTRAP_GATEWAY_KEY="${MG_AGENT_BOOTSTRAP_GATEWAY_KEY:-}"
MG_AGENT_BOOTSTRAP_CA_CERT="${MG_AGENT_BOOTSTRAP_CA_CERT:-}"
MG_RULES_RETRIES="${MG_RULES_RETRIES:-5}"
MG_RULES_RETRY_DELAY_SECONDS="${MG_RULES_RETRY_DELAY_SECONDS:-2}"

if [ -z "${MG_AGENT_BOOTSTRAP_EXTERNAL_ID:-}" ]; then
    echo "ERROR: MG_AGENT_BOOTSTRAP_EXTERNAL_ID is required (device MAC address or unique ID)."
    exit 1
fi
if [ -z "${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY:-}" ]; then
    echo "ERROR: MG_AGENT_BOOTSTRAP_EXTERNAL_KEY is required (device bootstrap password)."
    exit 1
fi

TENANT_ID="${MG_TENANT_ID:-}"
if [ -z "$TENANT_ID" ]; then
    echo "ERROR: MG_TENANT_ID is required."
    exit 1
fi

if [ -z "${MG_PAT:-}" ]; then
    echo "ERROR: MG_PAT is required."
    exit 1
fi

echo "=== Magistrala Mock Device Provisioning ==="
echo "Clients API (script):  ${MG_CLIENTS_API}"
echo "Channels API (script): ${MG_CHANNELS_API}"
echo "Rules API (script):    ${MG_RULES_API}"
echo "Bootstrap API:         ${MG_BOOTSTRAP_API}"
echo "Agent clients URL:     ${MG_AGENT_CLIENTS_URL}"
echo "Agent channels URL:    ${MG_AGENT_CHANNELS_URL}"
echo "Agent rules URL:       ${MG_AGENT_RULES_URL}"
echo "Tenant ID:             ${TENANT_ID}"
echo ""

TOKEN="${MG_PAT}"
echo "Step 1: Using PAT token (${#TOKEN} characters)."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
# service. It produces the rendered content the agent parses at startup.
# Binding slots:
#   mqtt_client  - the device Client (credentials)
#   telemetry    - the telemetry/data Channel (DataChan)
#   commands     - the commands/control Channel (CtrlChan)
build_profile_payload() {
    python3 - <<'PY'
import json

template = """{
  "device_id": "{{ .Device.ID }}",
  "external_id": "{{ .Device.ExternalID }}",
  "tenant_id": "{{ .Device.TenantID }}",
  "mqtt": {
    "url": "{{ index .Vars "mqtt_url" }}",
    "client_id": "{{ (index .Bindings "mqtt_client").ID }}",
    "secret": "{{ index (index .Bindings "mqtt_client").Secret "secret" }}"
  },
  "telemetry": {
    "channel_id": "{{ (index .Bindings "telemetry").ID }}",
    "topic": "{{ index (index .Bindings "telemetry").Snapshot "topic" }}"
  },
  "commands": {
    "channel_id": "{{ (index .Bindings "commands").ID }}"
  },
  "provision": {
    "clients_url": "{{ index .Vars "clients_url" }}",
    "channels_url": "{{ index .Vars "channels_url" }}",
    "rules_engine_url": "{{ index .Vars "rules_engine_url" }}",
    "token": "{{ index .Vars "provision_token" }}"
  }
}"""

payload = {
    "name": "agent-linux-device-profile",
    "description": "Bootstrap profile for Linux IoT gateway device running Magistrala Agent",
    "content_format": "json",
    "content_template": template,
    "binding_slots": [
        {
            "name": "mqtt_client",
            "type": "client",
            "required": True,
        },
        {
            "name": "telemetry",
            "type": "channel",
            "required": True,
        },
        {
            "name": "commands",
            "type": "channel",
            "required": True,
        },
    ],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# Build the Bootstrap Enrollment JSON payload.
# render_context supplies the static per-enrollment variables (.Vars.*)
# referenced in the profile template. Only mqtt_url is needed; all other
# agent settings are provided via environment variables at startup.
build_enrollment_payload() {
    PROFILE_ID="${PROFILE_ID}" \
        MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}" \
        MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}" \
        MG_AGENT_MQTT_URL="${MG_AGENT_MQTT_URL}" \
        MG_AGENT_CLIENTS_URL="${MG_AGENT_CLIENTS_URL}" \
        MG_AGENT_CHANNELS_URL="${MG_AGENT_CHANNELS_URL}" \
        MG_PAT="${MG_PAT}" \
        MG_AGENT_RULES_URL="${MG_AGENT_RULES_URL}" \
        MG_AGENT_BOOTSTRAP_CLIENT_CERT="${MG_AGENT_BOOTSTRAP_CLIENT_CERT}" \
        MG_AGENT_BOOTSTRAP_CLIENT_KEY="${MG_AGENT_BOOTSTRAP_CLIENT_KEY}" \
        MG_AGENT_BOOTSTRAP_CA_CERT="${MG_AGENT_BOOTSTRAP_CA_CERT}" \
        python3 - <<'PY'
import json
import os

payload = {
    "external_id": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_ID"],
    "external_key": os.environ["MG_AGENT_BOOTSTRAP_EXTERNAL_KEY"],
    "name": "agent-mock-device-config",
    "profile_id": os.environ["PROFILE_ID"],
    "status": "enabled",
    # SECURITY NOTE: provision_token (MG_PAT) is an operator-level Personal
    # Access Token that is persisted inside Magistrala's bootstrap config for
    # every gateway that runs this script. A compromised gateway therefore
    # exposes full operator authority over the Magistrala deployment. Before
    # using this in production, replace MG_PAT with a narrowly-scoped token
    # that only has permission to create clients/channels/rules within the
    # target tenant.
    "render_context": {
        "mqtt_url":          os.environ["MG_AGENT_MQTT_URL"],
        "clients_url":       os.environ["MG_AGENT_CLIENTS_URL"],
        "channels_url":      os.environ["MG_AGENT_CHANNELS_URL"],
        "provision_token":   os.environ["MG_PAT"],
        "rules_engine_url":  os.environ["MG_AGENT_RULES_URL"],
    },
    "client_cert": os.environ["MG_AGENT_BOOTSTRAP_GATEWAY_CERT"],
    "client_key":  os.environ["MG_AGENT_BOOTSTRAP_GATEWAY_KEY"],
    "ca_cert":     os.environ["MG_AGENT_BOOTSTRAP_CA_CERT"],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# Build the bindings payload that links profile slots to real resources.
build_bindings_payload() {
    CLIENT_ID="${CLIENT_ID}" \
        TELEMETRY_CHANNEL="${TELEMETRY_CHANNEL}" \
        COMMANDS_CHANNEL="${COMMANDS_CHANNEL}" \
        python3 - <<'PY'
import json
import os

payload = {
    "bindings": [
        {
            "slot":        "mqtt_client",
            "type":        "client",
            "resource_id": os.environ["CLIENT_ID"],
        },
        {
            "slot":        "telemetry",
            "type":        "channel",
            "resource_id": os.environ["TELEMETRY_CHANNEL"],
        },
        {
            "slot":        "commands",
            "type":        "channel",
            "resource_id": os.environ["COMMANDS_CHANNEL"],
        },
    ]
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

build_connect_payload() {
    local channel_id="$1"
    shift
    CHANNEL_ID="${channel_id}" \
        CLIENT_ID="${CLIENT_ID}" \
        CONN_TYPES="$*" \
        python3 - <<'PY'
import json
import os

payload = {
    "channel_ids": [os.environ["CHANNEL_ID"]],
    "client_ids": [os.environ["CLIENT_ID"]],
    "types": os.environ["CONN_TYPES"].split(),
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

# ---------------------------------------------------------------------------
# Step 2: Create the agent Client (device)
# ---------------------------------------------------------------------------
echo ""
echo "Step 2: Creating agent Client (device)..."
CLIENT_URL="${MG_CLIENTS_API}/${TENANT_ID}/clients"
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
# Step 3: Create Channels (telemetry + commands)
# ---------------------------------------------------------------------------
echo ""
echo "Step 3: Creating Channels (telemetry + commands)..."
CHANNEL_URL="${MG_CHANNELS_API}/${TENANT_ID}/channels"
echo "  API: ${CHANNEL_URL}"

TELEMETRY_PAYLOAD='{
  "name": "agent-telemetry",
  "description": "Agent telemetry/data channel (DataChan)",
  "metadata": {
    "type": "agent",
    "role": "telemetry"
  },
  "status": "enabled"
}'
TEL_RESPONSE=$(post_json "${CHANNEL_URL}" "${TELEMETRY_PAYLOAD}")
require_created "Telemetry channel creation" "${CHANNEL_URL}" "${TEL_RESPONSE}"
TEL_BODY=$(response_body "${TEL_RESPONSE}")

TELEMETRY_CHANNEL=$(echo "$TEL_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [ -z "$TELEMETRY_CHANNEL" ]; then
    echo "ERROR: Failed to create telemetry Channel."
    echo "Response: ${TEL_BODY}"
    exit 1
fi
echo "  Telemetry Channel ID: ${TELEMETRY_CHANNEL}"

COMMANDS_PAYLOAD='{
  "name": "agent-commands",
  "description": "Agent commands/control channel (CtrlChan)",
  "metadata": {
    "type": "agent",
    "role": "commands"
  },
  "status": "enabled"
}'
CMD_RESPONSE=$(post_json "${CHANNEL_URL}" "${COMMANDS_PAYLOAD}")
require_created "Commands channel creation" "${CHANNEL_URL}" "${CMD_RESPONSE}"
CMD_BODY=$(response_body "${CMD_RESPONSE}")

COMMANDS_CHANNEL=$(echo "$CMD_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [ -z "$COMMANDS_CHANNEL" ]; then
    echo "ERROR: Failed to create commands Channel."
    echo "Response: ${CMD_BODY}"
    exit 1
fi
echo "  Commands Channel ID:  ${COMMANDS_CHANNEL}"

# ---------------------------------------------------------------------------
# Step 3b: Connect Client to Channels
# ---------------------------------------------------------------------------
echo ""
echo "Step 3b: Connecting Client to Channels..."
CONNECT_URL="${MG_CHANNELS_API}/${TENANT_ID}/channels/connect"
echo "  API: ${CONNECT_URL}"

TELEMETRY_CONNECT_PAYLOAD=$(build_connect_payload "${TELEMETRY_CHANNEL}" Publish)
TELEMETRY_CONNECT_RESPONSE=$(post_json "${CONNECT_URL}" "${TELEMETRY_CONNECT_PAYLOAD}")
require_created "Telemetry channel connection" "${CONNECT_URL}" "${TELEMETRY_CONNECT_RESPONSE}"
echo "  ${CLIENT_ID} → ${TELEMETRY_CHANNEL} (Publish)"

COMMANDS_CONNECT_PAYLOAD=$(build_connect_payload "${COMMANDS_CHANNEL}" Publish Subscribe)
COMMANDS_CONNECT_RESPONSE=$(post_json "${CONNECT_URL}" "${COMMANDS_CONNECT_PAYLOAD}")
require_created "Commands channel connection" "${CONNECT_URL}" "${COMMANDS_CONNECT_RESPONSE}"
echo "  ${CLIENT_ID} → ${COMMANDS_CHANNEL} (Publish, Subscribe)"

# ---------------------------------------------------------------------------
# Step 4a: Create Bootstrap Profile (reuse if one with the same name exists)
# ---------------------------------------------------------------------------
echo ""
echo "Step 4a: Creating Bootstrap Profile..."
PROFILE_URL="${MG_BOOTSTRAP_API}/${TENANT_ID}/clients/bootstrap/profiles"
echo "  API: ${PROFILE_URL}"

PROFILE_PAYLOAD=$(build_profile_payload)
PROFILE_NAME=$(echo "${PROFILE_PAYLOAD}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null || echo "")

PROFILE_ID=""

PROFILE_LOOKUP=$(curl -sSL "${PROFILE_URL}?limit=100" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "")
PROFILE_ID=$(echo "${PROFILE_LOOKUP}" | PROFILE_NAME="${PROFILE_NAME}" python3 -c "
import sys, json, os
try:
    data = json.load(sys.stdin)
    profile_name = os.environ['PROFILE_NAME']
    for p in data.get('profiles', []):
        if p.get('name') == profile_name:
            print(p['id'])
            break
except Exception:
    pass
" 2>/dev/null || echo "")

if [ -n "${PROFILE_ID}" ]; then
    echo "  Reusing existing profile: ${PROFILE_ID}"
else
    PROFILE_RESPONSE=$(post_json "${PROFILE_URL}" "${PROFILE_PAYLOAD}")
    PROFILE_HTTP_CODE=$(response_code "${PROFILE_RESPONSE}")
    PROFILE_BODY=$(response_body "${PROFILE_RESPONSE}")

    if [ "${PROFILE_HTTP_CODE}" = "200" ] || [ "${PROFILE_HTTP_CODE}" = "201" ]; then
        PROFILE_ID=$(echo "${PROFILE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
        if [ -z "${PROFILE_ID}" ]; then
            echo "ERROR: Failed to extract Profile ID from response."
            echo "Response: ${PROFILE_BODY}"
            exit 1
        fi
        echo "  Profile ID: ${PROFILE_ID}"
    else
        echo "ERROR: Bootstrap Profile creation returned HTTP ${PROFILE_HTTP_CODE}."
        echo "Endpoint: ${PROFILE_URL}"
        echo "Response: ${PROFILE_BODY}"
        echo "Hint: A profile named '${PROFILE_NAME}' may already exist. Delete it or use a token with admin access."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Step 4b: Create Bootstrap Enrollment
# If an enrollment with the same external_id already exists, reuse it.
# ---------------------------------------------------------------------------
echo ""
echo "Step 4b: Creating Bootstrap Enrollment..."
ENROLL_URL="${MG_BOOTSTRAP_API}/${TENANT_ID}/clients/configs"
echo "  API: ${ENROLL_URL}"

ENROLL_LOOKUP=$(curl -sSL "${ENROLL_URL}?offset=0&limit=100" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "")
ENROLLMENT_ID=$(echo "${ENROLL_LOOKUP}" | MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}" python3 -c "
import sys, json, os
try:
    data = json.load(sys.stdin)
    ext_id = os.environ['MG_AGENT_BOOTSTRAP_EXTERNAL_ID']
    for c in data.get('configs', []):
        if c.get('external_id') == ext_id:
            print(c.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null || echo "")

if [ -n "${ENROLLMENT_ID}" ]; then
    echo "  Reusing existing enrollment: ${ENROLLMENT_ID}"
else
    ENROLL_PAYLOAD=$(build_enrollment_payload)
    ENROLL_HEADERS=$(mktemp)
    ENROLL_RESPONSE=$(curl -sSL -X POST "${ENROLL_URL}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -D "${ENROLL_HEADERS}" \
        -w "\n%{http_code}" \
        -d "${ENROLL_PAYLOAD}")
    ENROLL_HTTP_CODE=$(response_code "${ENROLL_RESPONSE}")
    ENROLL_BODY=$(response_body "${ENROLL_RESPONSE}")

    if [ "${ENROLL_HTTP_CODE}" = "200" ] || [ "${ENROLL_HTTP_CODE}" = "201" ]; then
        ENROLL_LOCATION=$(grep -i "^location:" "${ENROLL_HEADERS}" | tr -d '\r' | awk '{print $2}')
        ENROLLMENT_ID=$(basename "${ENROLL_LOCATION}")
        rm -f "${ENROLL_HEADERS}"

        if [ -z "${ENROLLMENT_ID}" ]; then
            echo "ERROR: Failed to extract Enrollment ID from Location header."
            exit 1
        fi
        echo "  Enrollment ID: ${ENROLLMENT_ID}"
    else
        echo "  Enrollment creation returned HTTP ${ENROLL_HTTP_CODE}, checking for existing enrollment..."
        rm -f "${ENROLL_HEADERS}"
        ENROLL_LOOKUP=$(curl -sSL "${ENROLL_URL}?offset=0&limit=100" \
            -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "")
        ENROLLMENT_ID=$(echo "${ENROLL_LOOKUP}" | MG_AGENT_BOOTSTRAP_EXTERNAL_ID="${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}" python3 -c "
import sys, json, os
try:
    data = json.load(sys.stdin)
    ext_id = os.environ['MG_AGENT_BOOTSTRAP_EXTERNAL_ID']
    for c in data.get('configs', []):
        if c.get('external_id') == ext_id:
            print(c.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null || echo "")
        if [ -n "${ENROLLMENT_ID}" ]; then
            echo "  Reusing existing enrollment: ${ENROLLMENT_ID}"
        else
            echo "ERROR: Bootstrap Enrollment creation returned HTTP ${ENROLL_HTTP_CODE}."
            echo "Endpoint: ${ENROLL_URL}"
            echo "Response: ${ENROLL_BODY}"
            exit 1
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 4c: Bind Resources
# Links mqtt_client → CLIENT_ID, telemetry → TELEMETRY_CHANNEL,
# and commands → COMMANDS_CHANNEL so the profile template can render
# credentials and channel IDs at bootstrap time.
# ---------------------------------------------------------------------------
echo ""
echo "Step 4c: Binding resources to enrollment..."
BINDINGS_URL="${MG_BOOTSTRAP_API}/${TENANT_ID}/clients/bootstrap/enrollments/${ENROLLMENT_ID}/bindings"
echo "  API: ${BINDINGS_URL}"

BINDINGS_PAYLOAD=$(build_bindings_payload)
BINDINGS_RESPONSE=$(put_json "${BINDINGS_URL}" "${BINDINGS_PAYLOAD}")
require_no_content "Bootstrap Bindings" "${BINDINGS_URL}" "${BINDINGS_RESPONSE}"
echo "  mqtt_client → ${CLIENT_ID}"
echo "  telemetry   → ${TELEMETRY_CHANNEL}"
echo "  commands    → ${COMMANDS_CHANNEL}"

# ---------------------------------------------------------------------------
# Step 5: Set up Rule Engine to store telemetry messages as SenML
# ---------------------------------------------------------------------------
echo ""
echo "Step 5: Configuring Rule Engine (save_senml) for telemetry channel..."
RULE_CONFIG_URL="${MG_RULES_API}/${TENANT_ID}/rules"
echo "  API: ${RULE_CONFIG_URL}"

RULE_PAYLOAD="{
  \"name\": \"agent-mock-device-storage-data\",
  \"tenant\": \"${TENANT_ID}\",
  \"input_channel\": \"${TELEMETRY_CHANNEL}\",
  \"input_topic\": \"msg\",
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
    "Rule Engine configuration for telemetry channel" \
    "${RULE_CONFIG_URL}" \
    "${RULE_PAYLOAD}" \
    "${MG_RULES_RETRIES}" \
    "${MG_RULES_RETRY_DELAY_SECONDS}"
echo "  Rule Engine configured for telemetry channel (save_senml)."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Resources created:"
echo "  Client ID:          ${CLIENT_ID}"
echo "  Client Secret:      ${CLIENT_SECRET}"
echo "  Telemetry Channel:  ${TELEMETRY_CHANNEL}"
echo "  Commands Channel:   ${COMMANDS_CHANNEL}"
echo "  Tenant ID:          ${TENANT_ID}"
echo "  Profile ID:         ${PROFILE_ID}"
echo "  Enrollment ID:      ${ENROLLMENT_ID}"
echo "  Bootstrap ID:       ${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}"
echo "  Bootstrap Key:      ${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}"
echo ""
echo ""
echo "=== Next Steps ==="
echo ""
echo "Bootstrap credentials for this device:"
echo "  MG_AGENT_BOOTSTRAP_EXTERNAL_ID=${MG_AGENT_BOOTSTRAP_EXTERNAL_ID}"
echo "  MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY}"
echo "  MG_AGENT_BOOTSTRAP_URL=${MG_BOOTSTRAP_API}/clients/bootstrap"
echo ""
echo "Pass these to the agent at runtime (env vars, systemd unit, k8s secret)."
echo ""
echo "Local dev quickstart (docker compose):"
echo "  MG_AGENT_BOOTSTRAP_EXTERNAL_ID=${MG_AGENT_BOOTSTRAP_EXTERNAL_ID} \\"
echo "  MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=${MG_AGENT_BOOTSTRAP_EXTERNAL_KEY} \\"
echo "  make run"
echo ""
echo "=== MQTT Connection Details ==="
echo "  Username: ${CLIENT_ID}"
echo "  Password: ${CLIENT_SECRET}"
echo "  Telemetry Channel: ${TELEMETRY_CHANNEL}"
echo "  Commands Channel:  ${COMMANDS_CHANNEL}"
echo "  Tenant:   ${TENANT_ID}"
echo ""
echo "=== Test MQTT Publishing ==="
echo ""
echo "Local (localhost:8883):"
echo "  mosquitto_pub -I \"agent-mock-device\" \\"
echo "    -u ${CLIENT_ID} \\"
echo "    -P ${CLIENT_SECRET} \\"
echo "    -t m/${TENANT_ID}/c/${TELEMETRY_CHANNEL}/msg \\"
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
echo "    -t m/${TENANT_ID}/c/${TELEMETRY_CHANNEL}/msg \\"
echo "    -m '[{\"n\":\"Temperature\",\"bu\":\"°C\",\"u\":\"°C\",\"v\":30}]'"
echo ""
echo "=== Deploy Node-RED Flow ==="
echo "  FLOWS=\$(cat examples/nodered/speed-flow.json | base64 -w 0)"
echo "  curl -s -X POST http://localhost:9999/nodered \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d \"{\\\"command\\\":\\\"nodered-deploy\\\",\\\"flows\\\":\\\"\$FLOWS\\\"}\""
