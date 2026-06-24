# MQTT Quickstart: Two Gateways, One Channel, Pub/Sub

Create two gateway entities and a channel, grant both publish & subscribe access, then test with Mosquitto.

## Terminology

| Atom term | What it is                             | Example                            |
| --------- | -------------------------------------- | ---------------------------------- |
| Tenant    | Top boundary                           | `factory-a`                        |
| Entity    | Anything that authenticates            | Gateway, device, human, service    |
| Resource  | Something protected by access rules    | Channel                            |
| Profile   | User-defined subtype of an entity kind | `gateway`, `sensor`, `water_meter` |
| Kind      | Authorization-relevant classification  | `human`, `device`, `service`       |

**Entity kind vs profile:** `kind` drives access control rules (guardrails, action applicability). `profile` is a UI label / JSON Schema selector and is **ignored by authorization**. A gateway is `kind: device, profile: "gateway"`.

## Prerequisites

- Atom stack running (`make up` in `docker/`)
- `curl`, `jq`, `mosquitto_pub`, `mosquitto_sub` installed
- Atom API at `http://localhost:8080`, MQTT at `localhost:1883`

## 1. Login as admin

```bash
ADMIN_TOKEN=$(
  curl -s -X POST http://localhost:8080/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"identifier": "admin", "secret": "12345678"}' | jq -r '.token // empty'
)
echo "ADMIN_TOKEN=$ADMIN_TOKEN"
```

## 2. Create a tenant

```bash
read -r TENANT_ID _ < <(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d '{"query":"mutation { createTenant(input: {name: \"demo-tenant\", alias: \"demo-tenant\"}) { id name alias } }"}' \
  | jq -r '.data.createTenant.id // empty'
)
echo "TENANT_ID=$TENANT_ID"
```

## 3. Create two gateway entities

Entities with `kind: device, profile: "gateway"`.

```bash
GATEWAY1_ID=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg tid "$TENANT_ID" '{
      query: "mutation($tid:ID!){createEntity(input:{kind:device,profile:\"gateway\",name:\"gw-a\",tenantId:$tid,attributes:{}}){id}}",
      variables: {tid: $tid}
    }')" | jq -r '.data.createEntity.id // empty'
)
echo "GATEWAY1_ID=$GATEWAY1_ID"

GATEWAY2_ID=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg tid "$TENANT_ID" '{
      query: "mutation($tid:ID!){createEntity(input:{kind:device,profile:\"gateway\",name:\"gw-b\",tenantId:$tid,attributes:{}}){id}}",
      variables: {tid: $tid}
    }')" | jq -r '.data.createEntity.id // empty'
)
echo "GATEWAY2_ID=$GATEWAY2_ID"
```

## 4. Create a channel (resource)

```bash
CHANNEL_ID=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg tid "$TENANT_ID" --arg oid "$GATEWAY1_ID" '{
      query: "mutation($tid:ID!,$oid:ID!){createResource(input:{kind:\"channel\",name:\"temperature\",tenantId:$tid,ownerId:$oid,attributes:{}}){id}}",
      variables: {tid: $tid, oid: $oid}
    }')" | jq -r '.data.createResource.id // empty'
)
echo "CHANNEL_ID=$CHANNEL_ID"
```

## 5. Create API keys (MQTT password)

```bash
APIKEY1=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg eid "$GATEWAY1_ID" '{
      query: "mutation($eid:ID!){createApiKey(entityId:$eid,input:{description:\"gw-a-key\"}){key}}",
      variables: {eid: $eid}
    }')" | jq -r '.data.createApiKey.key // empty'
)
echo "APIKEY1=$APIKEY1"

APIKEY2=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg eid "$GATEWAY2_ID" '{
      query: "mutation($eid:ID!){createApiKey(entityId:$eid,input:{description:\"gw-b-key\"}){key}}",
      variables: {eid: $eid}
    }')" | jq -r '.data.createApiKey.key // empty'
)
echo "APIKEY2=$APIKEY2"
```

API keys are shown once. Save them.

## 6. Look up action IDs

```bash
PUBLISH_ACTION_ID=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d '{"query":"{actions(limit:100){items{id name}}}"}' \
  | jq -r '.data.actions.items[] | select(.name=="publish") | .id // empty'
)
echo "PUBLISH_ACTION_ID=$PUBLISH_ACTION_ID"

SUBSCRIBE_ACTION_ID=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d '{"query":"{actions(limit:100){items{id name}}}"}' \
  | jq -r '.data.actions.items[] | select(.name=="subscribe") | .id // empty'
)
echo "SUBSCRIBE_ACTION_ID=$SUBSCRIBE_ACTION_ID"
```

## 7. Create a Permission Block

Scope = this exact channel, allow publish + subscribe.

```bash
PB_RESPONSE=$(
  curl -s -X POST http://localhost:8080/graphql \
    -H 'Authorization: Bearer '$ADMIN_TOKEN \
    -H 'Content-Type: application/json' \
    -d "$(jq -n \
      --arg tid "$TENANT_ID" \
      --arg aid1 "$PUBLISH_ACTION_ID" \
      --arg aid2 "$SUBSCRIBE_ACTION_ID" \
      --arg cid "$CHANNEL_ID" \
      --arg sm "object" \
      --arg ok "resource" \
      --arg ot "channel" \
      --arg ef "allow" \
      '{
        query: "mutation($tid:ID!,$aid1:ID!,$aid2:ID!,$cid:ID!,$sm:String!,$ok:String!,$ot:String!,$ef:String!){
          createPermissionBlock(input:{
            tenantId:$tid,
            scopeMode:$sm,
            objectKind:$ok,
            objectType:$ot,
            objectId:$cid,
            effect:$ef,
            actionIds:[$aid1,$aid2]
          }){id}
        }",
        variables: {
          tid: $tid,
          aid1: $aid1,
          aid2: $aid2,
          cid: $cid,
          sm: $sm,
          ok: $ok,
          ot: $ot,
          ef: $ef
        }
      }')"
)
echo "$PB_RESPONSE" | jq .
PB_ID=$(echo "$PB_RESPONSE" | jq -r '.data.createPermissionBlock.id // empty')
echo "PB_ID=$PB_ID"
```

If `PB_ID` is empty, inspect `$PB_RESPONSE` for errors.

## 8. Grant both gateways access via Direct Policies

```bash
curl -s -X POST http://localhost:8080/graphql \
  -H 'Authorization: Bearer '$ADMIN_TOKEN \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg tid "$TENANT_ID" --arg sid "$GATEWAY1_ID" --arg pbid "$PB_ID" '{
    query: "mutation($tid:ID!,$sid:ID!,$pbid:ID!){createDirectPolicy(input:{tenantId:$tid,subjectKind:entity,subjectId:$sid,permissionBlockId:$pbid}){id}}",
    variables: {tid: $tid, sid: $sid, pbid: $pbid}
  }')" | jq .

curl -s -X POST http://localhost:8080/graphql \
  -H 'Authorization: Bearer '$ADMIN_TOKEN \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg tid "$TENANT_ID" --arg sid "$GATEWAY2_ID" --arg pbid "$PB_ID" '{
    query: "mutation($tid:ID!,$sid:ID!,$pbid:ID!){createDirectPolicy(input:{tenantId:$tid,subjectKind:entity,subjectId:$sid,permissionBlockId:$pbid}){id}}",
    variables: {tid: $tid, sid: $sid, pbid: $pbid}
  }')" | jq .
```

## 9. Test with Mosquitto

**Terminal 1 — subscribe** (gw-b listens):

```bash
mosquitto_sub -h localhost -p 1883 \
  -u "$GATEWAY2_ID" -P "$APIKEY2" \
  -t "m/$TENANT_ID/c/$CHANNEL_ID/#" \
  -q 1 -d
```

**Terminal 2 — publish** (gw-a sends):

```bash
mosquitto_pub -h localhost -p 1883 \
  -u "$GATEWAY1_ID" -P "$APIKEY1" \
  -t "m/$TENANT_ID/c/$CHANNEL_ID/test" \
  -m '{"temp": 23.5}' \
  -q 1 -d
```

For TLS (port `8883`), add `--cafile /path/to/ca.crt`.

## Cleanup

```bash
curl -s -X POST http://localhost:8080/graphql \
  -H 'Authorization: Bearer '$ADMIN_TOKEN \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg id "$TENANT_ID" '{
    query: "mutation($id:ID!){deleteTenant(id:$id)}",
    variables: {id: $id}
  }')"
```
