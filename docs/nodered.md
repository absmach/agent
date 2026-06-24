# Agent + Node-RED Integration

This guide explains how to run the Magistrala Agent with Node-RED support using a mock Linux device in Docker.

## Architecture

<p align="center">
  <img src="img/nodered-architecture.svg" alt="Agent + Node-RED Architecture" width="100%"/>
</p>

## Quick Start

### 1. Build the Agent Docker image

```bash
make all && make dockers_dev
```

### 2. Start the stack

```bash
make run
```

This starts: Agent + UI (:9999), Node-RED (:1880).

### 3. Verify services

```bash
# Check agent health
curl http://localhost:9999/health

# Ping Node-RED via agent
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-ping"}'

# Open the Agent UI
open http://localhost:9999

# Open Node-RED UI
open http://localhost:1880
```

## Provisioning with Magistrala

If you have a running Magistrala instance, use the provisioning script to automatically create Clients, Channels, Bootstrap Profile resources, and Rule Engine rules:

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_PAT="<personal-access-token>"
export MG_DOMAIN_ID="<domain-id>"
make run_provision
```

Use your real PAT in the shell, but do not commit it to files. The agent and Node-RED do not consume a generated `config.toml`; they fetch the rendered bootstrap profile at startup.

The PAT used for provisioning must be able to create bootstrap configs, rules, clients, and channels in the target domain. The script expects scopes such as:

- `bootstrap:create`
- `rules:create`
- `clients:create`
- `clients:view`
- `clients:connect_to_channel`
- `channels:create`
- `channels:view`
- `channels:connect_client`

Or with a custom API URL:

```bash
export MG_API=https://my-instance/api
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_DOMAIN_ID="<domain-id>"
export MG_PAT="<pat>"
make run_provision
```

For Magistrala Cloud specifically, use:

```bash
export MG_API=https://cloud.magistrala.absmach.eu/api
export MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883
export MG_AGENT_MQTT_SKIP_TLS=false
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_DOMAIN_ID="<domain-id>"
export MG_PAT="<pat>"
make run_provision
```

That combination targets the cloud APIs for provisioning and the cloud MQTT broker for runtime messaging.

Or run the script directly:

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_PAT="<personal-access-token>"
export MG_DOMAIN_ID="<domain-id>"
bash scripts/provision.sh
```

This will:

1. Create a Client (device) with credentials
2. Create telemetry and commands Channels
3. Create a Bootstrap Profile and Enrollment with `external_id` and `external_key`
4. Bind the profile slots to the provisioned client and channels
5. Configure a Rule Engine rule with `save_senml` output for telemetry messages

**Alternatively**, if you prefer to set up resources manually via the Magistrala UI or API, create the Client, telemetry Channel, commands Channel, Bootstrap Profile, Enrollment, bindings, and Rule Engine rule, then edit `docker/.env` with the bootstrap values:

```env
MG_AGENT_BOOTSTRAP_URL=http://bootstrap:9013/clients/bootstrap
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<external-id>
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<external-key>
```

Then restart the agent:

```bash
docker compose up -d
```

## Deploying Node-RED Flows

### Via Agent UI

Open `http://localhost:9999` in a browser. The **Node-RED** panel lets you:

- **Ping** — check that Node-RED is reachable
- **State** — get the current runtime state
- **Get Flows** — fetch and inspect the deployed flows (pretty-printed JSON)
- **Select JSON File** — pick a local `.json` flow file
- **Deploy Flows** — **replaces all currently running flows** in Node-RED with the selected file. Any flows that were running before will be stopped and removed.
- **Add Flow** — **adds the selected file as a new flow tab** alongside existing flows without removing anything that is already running.

All responses are shown inline with the command label. The file is base64-encoded in the browser before being sent to the agent.

### Via HTTP API

```bash
# Deploy a flow (flow JSON must be base64 encoded)
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d "{\"command\":\"nodered-deploy\",\"flows\":\"$FLOWS\"}"

# Add a flow tab (non-destructive, flow JSON must be base64 encoded)
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d "{\"command\":\"nodered-add-flow\",\"flows\":\"$FLOWS\"}"

# Fetch current flows
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-flows"}'

# Ping Node-RED
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-ping"}'

# Get flow state
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-state"}'
```

### Via MQTT (from Magistrala cloud)

Send a SenML array to `m/<domain-id>/c/<commands-channel-id>/req`:

Supported commands:

- `nodered-deploy,<base64-flow>` — **Replace all running flows** with the provided flow JSON
- `nodered-add-flow,<base64-flow>` — **Add a new flow tab** alongside existing running flows
- `nodered-flows` — Fetch current flows
- `nodered-state` — Get runtime state
- `nodered-ping` — Check Node-RED availability

### Via Control command

```json
[
  {
    "bn": "uuid:",
    "n": "control",
    "vs": "nodered-deploy,<base64-encoded-flow-json>"
  }
]
```

## Example Flows

### Default flow (`docker/nodered/flows.json`)

Seeded into Node-RED on first start. It periodically publishes SenML temperature and humidity readings to the Magistrala data channel.

### Speed sensor flow (`examples/nodered/speed-flow.json`)

A ready-to-deploy example that publishes `speed` (km/h), `rpm`, and `gear` SenML records every 15 seconds. Use it to test remote flow deployment end-to-end.

### Modbus holding register flow (`examples/nodered/modbus-flow.json`)

Simulates polling 4 Modbus TCP holding registers (FC03) every 10 seconds and publishing SenML records to Magistrala:

| Register | Measurement          | Unit |
| -------- | -------------------- | ---- |
| HR0      | Voltage              | V    |
| HR1      | Current (scaled ×10) | A    |
| HR2      | Power                | W    |
| HR3      | Temperature          | °C   |

The simulation function node can be replaced with a real `modbus-read` node when a physical Modbus TCP slave is available.

**Deploy via Magistrala MQTT:**

```bash
# 1. Encode the flow
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

# 2. Publish the deploy command
mosquitto_pub \
  -h <mqtt-host> -p 8883 \
  --capath /etc/ssl/certs \
  -I "agent-mock-device" \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

The agent will:

1. Receive the SenML message over MQTT
2. Base64-decode the flow JSON
3. Patch the MQTT `clientid` in the flow to `<client-id>-nr` (prevents session conflict with the agent itself)
4. `POST` the flows to Node-RED's REST API
5. Publish the result back to the control channel

**Verify the deployment:**

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 \
  --capath /etc/ssl/certs \
  -I "agent-mock-device" \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-2:", "n":"nodered", "vs":"nodered-flows"}]'
```

The agent logs will show:

```json
{
  "level": "INFO",
  "msg": "NodeRed command \"nodered-deploy,...\" completed successfully.",
  "duration": "...",
  "uuid": "req-1"
}
```

Node-RED will start publishing speed data to the telemetry topic within 3 seconds of deployment. The agent normalises all `m/.../c/.../data` and `m/.../c/.../gateway/telemetry` topics in the flow to the rendered telemetry channel: `m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry`.

## Configuration

The Node-RED URL is configured via environment variable:

- **Environment variable**: `MG_AGENT_NODERED_URL` (default: `http://localhost:1880/`)

Device identity, MQTT credentials, domain ID, and telemetry/commands channel IDs come from the rendered bootstrap profile.

## Topic Map

| Direction        | Topic                                                | QoS | Description                                            |
| ---------------- | ---------------------------------------------------- | --- | ------------------------------------------------------ |
| Cloud → Agent    | `m/<domain-id>/c/<ctrl-chan>/req`                    | 1   | Node-RED commands via `nodered` or `control` subsystem |
| Agent → Cloud    | `m/<domain-id>/c/<ctrl-chan>/res`                    | 1   | Command response                                       |
| Node-RED → Cloud | `m/<domain-id>/c/<telemetry-chan>/gateway/telemetry` | 0   | SenML telemetry published by deployed flows            |

## MQTT Test Recipes

All recipes use the **commands channel request topic**: `m/<domain-id>/c/<commands-channel-id>/req`.

Responses are published to: `m/<domain-id>/c/<commands-channel-id>/res`.

### Subscribe to responses

```bash
mosquitto_sub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<commands-channel-id>/res" \
    -v
```

### Ping Node-RED

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "nr-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-ping"}]'
```

**Expected response:**

```json
[
  {
    "bn": "req-1",
    "bt": 1781261269.1195753,
    "n": "nodered",
    "vs": "{\"httpNodeRoot\":\"/\",\"version\":\"4.1.10\",\"context\":{\"default\":\"memory\",\"stores\":[\"memory\"]},\"libraries\":[{\"id\":\"local\",\"label\":\"editor:library.types.local\",\"user\":false,\"icon\":\"font-awesome/fa-hdd-o\"},{\"id\":\"examples\",\"label\":\"editor:library.types.examples\",\"user\":false,\"icon\":\"font-awesome/fa-life-ring\",\"types\":[\"flows\"],\"readOnly\":true}],\"flowEncryptionType\":\"disabled\",\"diagnostics\":{\"enabled\":true,\"ui\":true},\"telemetryEnabled\":false,\"runtimeState\":{\"enabled\":false,\"ui\":false},\"functionExternalModules\":true,\"functionTimeout\":0,\"tlsConfigDisableLocalFiles\":false,\"editorTheme\":{\"projects\":{\"enabled\":false},\"languages\":[\"de\",\"en-US\",\"es-ES\",\"fr\",\"ja\",\"ko\",\"pt-BR\",\"ru\",\"zh-CN\",\"zh-TW\"]}}"
  }
]
```

### Get Node-RED runtime state

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "nr-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-state"}]'
```

**Expected response:**

```json
[
  {
    "bn": "req-1",
    "bt": 1781865951.7412772,
    "n": "nodered",
    "vs": "{\"state\":\"start\"}"
  }
]
```

### Fetch current flows

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "nr-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-flows"}]'
```

**Expected response (after deploying speed-flow.json, truncated):**

```json
[
  {
    "bn": "req-1",
    "bt": 1781865982.932532,
    "n": "nodered",
    "vs": "[{\"id\":\"flow-speed-sensor\",\"type\":\"tab\",\"label\":\"Speed Sensor Flow\",\"disabled\":false,\"info\":\"Publishes SenML speed data to Magistrala cloud every 15s via MQTT over TLS.\"},{\"id\":\"mqtt-broker-config\",\"type\":\"mqtt-broker\",\"name\":\"Magistrala Cloud MQTT\",\"broker\":\"host.docker.internal\",\"port\":\"8883\",\"clientid\":\"<client-id>-nr\",\"usetls\":true,\"tls\":\"magistrala-agent-tls\",\"credentials\":{\"user\":\"<client-id>\",\"password\":\"<client-secret>\"},\"z\":\"\"},{\"id\":\"inject-speed\",\"type\":\"inject\",\"z\":\"flow-speed-sensor\",\"name\":\"Every 15s\",\"repeat\":\"15\",\"once\":true,\"onceDelay\":3,\"wires\":[[\"build-speed-senml\"]]},{\"id\":\"build-speed-senml\",\"type\":\"function\",\"z\":\"flow-speed-sensor\",\"func\":\"var now = Date.now() * 1e6;\\nmsg.payload = JSON.stringify([\\n    {\\\"bn\\\": \\\"speed-sensor:\\\", \\\"bt\\\": now, \\\"n\\\": \\\"speed\\\", \\\"u\\\": \\\"km/h\\\", \\\"v\\\": 60 + Math.random() * 40}\\n]);\\nmsg.topic = \\\"m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry\\\";\\nreturn msg;\",\"wires\":[[\"mqtt-pub-speed\",\"debug-speed\"]]}]"
  }
]
```

Note the normalisations the agent applied: `clientid` suffixed with `-nr`, `usetls` set to `true`, `tls` set to `magistrala-agent-tls`, and the topic rewritten to `m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry`.

### Deploy flows (replace all)

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "deploy-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

**Expected response** (Node-RED returns 204 No Content on successful full deploy):

```json
[
  {
    "bn": "req-1",
    "bt": 1781865982.932532,
    "n": "nodered",
    "vs": ""
  }
]
```

> **Warning:** `nodered-deploy` replaces **all** running flows. Use `nodered-add-flow` to add without replacing.

### Add a flow tab (non-destructive)

```bash
FLOWS=$(cat examples/nodered/modbus-flow.json | base64 -w 0)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "addflow-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-add-flow,$FLOWS\"}]"
```

**Expected response:**

```json
[
  {
    "bn": "req-1",
    "bt": 1781866008.2599385,
    "n": "nodered",
    "vs": "{\"id\":\"53c5e22d806c0d04\"}"
  }
]
```

The response contains the new flow tab ID. Node IDs in the submitted flow are rekeyed (replaced with fresh `nr-` prefixed IDs) before being sent to Node-RED, so example flows with fixed IDs can be added alongside existing flows without duplicate-ID conflicts.

### Verify telemetry is publishing

After deploying a flow, subscribe to the telemetry topic to confirm Node-RED is publishing SenML data:

```bash
mosquitto_sub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "tel-$(date +%s)" \
    -t "m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry" \
    -v
```

**Expected output (speed-flow.json, every 15s):**

```
m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry [{"bn":"speed-sensor:","bt":1781866061271000000,"n":"speed","u":"km/h","v":82.4},{"n":"rpm","u":"rpm","v":1923},{"n":"gear","u":"1","v":3}]
```

**Expected output (modbus-flow.json, every 10s):**

```
m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry [{"bn":"modbus-device:","bt":1781866061271000000,"n":"hr0","u":"V","v":236},{"n":"hr1","u":"A","v":11.2},{"n":"hr2","u":"W","v":2643},{"n":"hr3","u":"Cel","v":48}]
```

### Error handling

Unknown commands and missing flow arguments return an error response on the response topic:

```bash
# Unknown command
mosquitto_pub ... -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-unknown"}]'
# Response: [{"bn":"req-1","n":"nodered","vs":"failed to execute node-red operation : Unknown command"}]

# Deploy without flow argument
mosquitto_pub ... -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-deploy"}]'
# Response: [{"bn":"req-1","n":"nodered","vs":"invalid command"}]

# Invalid base64 payload
mosquitto_pub ... -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-deploy,%%%bad"}]'
# Response: [{"bn":"req-1","n":"nodered","vs":"failed to execute node-red operation : ..."}]
```

### Deploy via control subsystem

Node-RED commands can also be sent via the `control` subsystem:

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ctrl-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\",\"n\":\"control\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

## Configuration

### Environment Variables

| Variable                          | Default                                   | Description                |
| --------------------------------- | ----------------------------------------- | -------------------------- |
| `MG_AGENT_NODERED_URL`            | `http://localhost:1880/`                  | Node-RED REST API base URL |
| `MG_AGENT_BOOTSTRAP_URL`          | `http://bootstrap:9013/clients/bootstrap` | Bootstrap fetch URL        |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`  |                                           | Bootstrap external ID      |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` |                                           | Bootstrap external key     |
