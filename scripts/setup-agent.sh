#!/bin/bash
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0
#
# Setup script: provisions Atom resources needed by the agent and writes the
# agent-config.json so the agent starts with a valid tenant, gateway identity,
# and channel IDs (no bootstrap needed).
#
# Usage:
#   export MG_PAT=<admin-jwt-token>
#   bash scripts/setup-agent.sh
#
# On success it prints env-var exports you can source:
#   source <(bash scripts/setup-agent.sh)
#
# IMPORTANT: MG_PAT (admin JWT from /auth/login) expires in ~1 hour.
# Re-run this script after expiry to get a fresh token and new resources.

set -euo pipefail

ATOM_URL="${MG_AGENT_ATOM_URL:-${ATOM_URL:-http://localhost:8080/graphql}}"
ATOM_AUTH_URL="${ATOM_AUTH_URL:-http://localhost:8080/auth/login}"

# ── 0. Authenticate ──────────────────────────────────────────────────────────
if [ -z "${MG_PAT:-}" ]; then
  echo "No MG_PAT set, logging in as admin..." >&2
  MG_PAT=$(curl -s -X POST "$ATOM_AUTH_URL" \
    -H 'Content-Type: application/json' \
    -d '{"identifier":"admin","secret":"12345678"}' | jq -r '.token // empty')
fi
if [ -z "$MG_PAT" ]; then echo "ERROR: no MG_PAT"; exit 1; fi

echo "MG_PAT expires in ~1 hour — consider re-running this script for a fresh token." >&2

gql() {
  curl -s "$ATOM_URL" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MG_PAT" \
    -d @-
}

# ── 1. Tenant (use existing or create) ──────────────────────────────────────
# Look for tenant by name, otherwise use the first tenant.
KNOWN_TENANT_NAME="${MG_KNOWN_TENANT_NAME:-test-tenant-agent}"
TENANTS_JSON=$(echo '{ "query": "{ tenants(limit:100) { items { id name } } }" }' | gql)
TENANT_ID=$(echo "$TENANTS_JSON" | jq -r --arg n "$KNOWN_TENANT_NAME" '.data.tenants.items[] | select(.name==$n) | .id // empty' | head -1)
if [ -z "$TENANT_ID" ]; then
  TENANT_ID=$(echo "$TENANTS_JSON" | jq -r '.data.tenants.items[0].id // empty')
fi
if [ -z "$TENANT_ID" ]; then
  TENANT_ID=$(jq -n '{ query: "mutation($n:String!){createTenant(input:{name:$n}){id}}", variables: {n: "agent-tenant"} }' | gql | jq -r '.data.createTenant.id')
fi
echo "TENANT_ID=$TENANT_ID" >&2

# ── 2. Gateway entity (delete existing if name taken, then create fresh) ───
GATEWAY_NAME="${MG_GATEWAY_NAME:-agent-gateway}"
# Delete ALL existing entities with this name to avoid "already exists" error.
ALL_ENTITIES=$(echo '{ "query": "{ entities(limit:100) { items { id name } } }" }' | gql)
EXISTING_IDS=$(echo "$ALL_ENTITIES" | jq -r --arg n "$GATEWAY_NAME" '.data.entities.items[] | select(.name==$n) | .id // empty')
if [ -n "$EXISTING_IDS" ]; then
  for eid in $EXISTING_IDS; do
    echo "Deleting stale gateway entity $eid ..." >&2
    jq -n --arg id "$eid" '{
      query: "mutation($id:ID!){deleteEntity(id:$id)}",
      variables: {id: $id}
    }' | gql > /dev/null
  done
fi

GATEWAY_ID=$(jq -n --arg tid "$TENANT_ID" --arg gn "$GATEWAY_NAME" '{
  query: "mutation($tid:ID!,$gn:String!){createEntity(input:{kind:device,name:$gn,tenantId:$tid,attributes:{}}){id}}",
  variables: {tid: $tid, gn: $gn}
}' | gql | jq -r '.data.createEntity.id // empty')
if [ -z "$GATEWAY_ID" ]; then
  echo "ERROR: failed to create entity" >&2
  exit 1
fi
echo "GATEWAY_ID=$GATEWAY_ID" >&2

# ── 3. API key for MQTT ─────────────────────────────────────────────────────
GATEWAY_KEY=$(jq -n --arg eid "$GATEWAY_ID" '{
  query: "mutation($eid:ID!){createApiKey(entityId:$eid,input:{description:\"agent-mqtt\"}){key}}",
  variables: {eid: $eid}
}' | gql | jq -r '.data.createApiKey.key // empty')
echo "GATEWAY_KEY=${GATEWAY_KEY:0:30}..." >&2

# ── 4. Resources (channels) ─────────────────────────────────────────────────
CTRL_CHAN_ID=$(jq -n --arg tid "$TENANT_ID" --arg oid "$GATEWAY_ID" '{
  query: "mutation($tid:ID!,$oid:ID!){createResource(input:{kind:\"channel\",name:\"agent-ctrl\",tenantId:$tid,ownerId:$oid,attributes:{}}){id}}",
  variables: {tid: $tid, oid: $oid}
}' | gql | jq -r '.data.createResource.id // empty')
echo "CTRL_CHAN_ID=$CTRL_CHAN_ID" >&2

DATA_CHAN_ID=$(jq -n --arg tid "$TENANT_ID" --arg oid "$GATEWAY_ID" '{
  query: "mutation($tid:ID!,$oid:ID!){createResource(input:{kind:\"channel\",name:\"agent-data\",tenantId:$tid,ownerId:$oid,attributes:{}}){id}}",
  variables: {tid: $tid, oid: $oid}
}' | gql | jq -r '.data.createResource.id // empty')
echo "DATA_CHAN_ID=$DATA_CHAN_ID" >&2

# ── 5. Connect gateway ↔ channels (permission blocks + direct policies) ─────
ACTIONS=$(echo '{ "query": "{ actions(limit:100) { items { id name } } }" }' | gql)
PUB_AID=$(echo "$ACTIONS" | jq -r '.data.actions.items[] | select(.name=="publish") | .id')
SUB_AID=$(echo "$ACTIONS" | jq -r '.data.actions.items[] | select(.name=="subscribe") | .id')

for CHAN_ID in "$CTRL_CHAN_ID" "$DATA_CHAN_ID"; do
  PB_ID=$(jq -n --arg tid "$TENANT_ID" --arg cid "$CHAN_ID" --arg pid "$PUB_AID" --arg sid "$SUB_AID" '{
    query: "mutation($tid:ID!,$cid:ID!,$pid:ID!,$sid:ID!){createPermissionBlock(input:{tenantId:$tid,scopeMode:\"object\",objectKind:\"resource\",objectType:\"resource:channel\",objectId:$cid,effect:allow,actionIds:[$pid,$sid]}){id}}",
    variables: {tid: $tid, cid: $cid, pid: $pid, sid: $sid}
  }' | gql | jq -r '.data.createPermissionBlock.id // empty')

  jq -n --arg tid "$TENANT_ID" --arg sid "$GATEWAY_ID" --arg pbid "$PB_ID" '{
    query: "mutation($tid:ID!,$sid:ID!,$pbid:ID!){createDirectPolicy(input:{tenantId:$tid,subjectKind:entity,subjectId:$sid,permissionBlockId:$pbid}){id}}",
    variables: {tid: $tid, sid: $sid, pbid: $pbid}
  }' | gql > /dev/null
done

# ── 6. Write agent-config.json (flat key-value store) ──────────────────────
# NOTE: MQTT URL uses plain TCP (port 1883) for local FluxMQ.
# For TLS/SSL use ssl://host:8883 and set MG_AGENT_MQTT_SKIP_TLS=false.
mkdir -p build
cat > build/agent-config.json <<ENDJSON
{
  "tenant_id": "$TENANT_ID",
  "channels_ctrl_id": "$CTRL_CHAN_ID",
  "channels_data_id": "$DATA_CHAN_ID",
  "mqtt_url": "tcp://host.docker.internal:1883",
  "mqtt_username": "$GATEWAY_ID",
  "mqtt_password": "$GATEWAY_KEY",
  "provision_token": "$MG_PAT"
}
ENDJSON

echo "Wrote build/agent-config.json" >&2

# ── 7. Output env vars ──────────────────────────────────────────────────────
cat <<ENV
MG_PAT="$MG_PAT"
TENANT_ID="$TENANT_ID"
GATEWAY_ID="$GATEWAY_ID"
GATEWAY_KEY="$GATEWAY_KEY"
CTRL_CHAN_ID="$CTRL_CHAN_ID"
DATA_CHAN_ID="$DATA_CHAN_ID"
PROVISION_TOKEN="$MG_PAT"
ENV
