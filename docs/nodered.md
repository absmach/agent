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

This starts: Agent (:9999), Node-RED (:1880), Agent UI (:9999).

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

Open `http://localhost:3002` in a browser. The **Node-RED** panel lets you:

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

Node-RED will start publishing speed data to the telemetry topic from the rendered profile, normally `m/<domain-id>/c/<telemetry-channel-id>/msg`, within 3 seconds of deployment.

## Configuration

The Node-RED URL is configured via environment variable:

- **Environment variable**: `MG_AGENT_NODERED_URL` (default: `http://localhost:1880/`)

Device identity, MQTT credentials, domain ID, and telemetry/commands channel IDs come from the rendered bootstrap profile.

## Topic Map

| Direction     | Topic                             | QoS | Description                                            |
| ------------- | --------------------------------- | --- | ------------------------------------------------------ |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/req` | 1   | Node-RED commands via `nodered` or `control` subsystem |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/res` | 1   | Command response                                       |

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
-h localhost -p 1883 \
-u faff2028-a7ba-4d11-8581-d9bbe9e1f75b -P ce6b440b-105a-40be-abf8-80f4c72938fb --id "nr-$(date +%s)" \
-t "m/e9692c28-b730-4797-8a15-2e25c08f9641/c/bc9a0af7-6d0f-4806-aa5a-61d68c0a7cf7/req" \
    -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-state"}]'
```

### Fetch current flows

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "nr-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"nodered", "vs":"nodered-flows"}]'
```

**Expected response (truncated):**

```json
[
  {
    "bn": "req-1",
    "bt": 1781261340.08909,
    "n": "nodered",
    "vs": "[{\"id\":\"flow-magistrala-agent\",\"type\":\"tab\",\"label\":\"Magistrala Agent Flow\",\"disabled\":false,\"info\":\"Publishes SenML sensor data to Magistrala cloud every 30s via MQTT over TLS.\"},{\"id\":\"mqtt-broker-config\",\"type\":\"mqtt-broker\",\"name\":\"Magistrala Cloud MQTT\",\"broker\":\"host.docker.internal\",\"port\":\"8883\",\"clientid\":\"ffec2491-0de1-4051-9e75-ad2e2d241627-nr\",\"autoConnect\":true,\"usetls\":true,\"protocolVersion\":\"4\",\"keepalive\":\"60\",\"cleansession\":true,\"autoUnsubscribe\":true,\"credentials\":{\"user\":\"ffec2491-0de1-4051-9e75-ad2e2d241627\",\"password\":\"30c775d7-3504-42c6-976c-52c02474bf2f\"},\"birthTopic\":\"\",\"closeTopic\":\"\",\"willTopic\":\"\",\"z\":\"\",\"tls\":\"magistrala-agent-tls\"},{\"id\":\"inject-sensor\",\"type\":\"inject\",\"z\":\"flow-magistrala-agent\",\"name\":\"Every 30s\",\"props\":[{\"p\":\"payload\",\"v\":\"\",\"vt\":\"date\"}],\"repeat\":\"30\",\"crontab\":\"\",\"once\":true,\"onceDelay\":5,\"topic\":\"\",\"payload\":\"\",\"payloadType\":\"date\",\"x\":150,\"y\":160,\"wires\":[[\"build-senml\"]]},{\"id\":\"build-senml\",\"type\":\"function\",\"z\":\"flow-magistrala-agent\",\"name\":\"Build SenML payload\",\"func\":\"var now = Date.now() * 1e6;\\nmsg.payload = JSON.stringify([\\n    {\\\"bn\\\": \\\"nodered:\\\", \\\"bt\\\": now, \\\"n\\\": \\\"temperature\\\", \\\"u\\\": \\\"Cel\\\", \\\"v\\\": 22.5 + Math.random() * 2},\\n    {\\\"n\\\": \\\"humidity\\\", \\\"u\\\": \\\"%\\\", \\\"v\\\": 55.0 + Math.random() * 5}\\n]);\\nmsg.topic = \\\"m/e9692c28-b730-4797-8a15-2e25c08f9641/c/b465a688-c1ca-417d-a36f-71f6f1be2409/msg\\\";\\nreturn msg;\",\"outputs\":1,\"x\":380,\"y\":160,\"wires\":[[\"mqtt-pub-data\",\"debug-output\"]]},{\"id\":\"mqtt-pub-data\",\"type\":\"mqtt out\",\"z\":\"flow-magistrala-agent\",\"name\":\"Publish to Magistrala\",\"topic\":\"\",\"qos\":\"0\",\"retain\":\"false\",\"broker\":\"mqtt-broker-config\",\"x\":640,\"y\":140,\"wires\":[]},{\"id\":\"debug-output\",\"type\":\"debug\",\"z\":\"flow-magistrala-agent\",\"name\":\"Debug\",\"active\":true,\"tosidebar\":true,\"console\":false,\"complete\":\"payload\",\"x\":620,\"y\":200,\"wires\":[]},{\"id\":\"magistrala-agent-tls\",\"type\":\"tls-config\",\"name\":\"Magistrala MQTT TLS\",\"cert\":\"\",\"key\":\"\",\"ca\":\"\",\"certname\":\"\",\"keyname\":\"\",\"caname\":\"\",\"servername\":\"\",\"verifyservercert\":false,\"alpnprotocol\":\"\"}]"
  }
]
```

### Deploy flows (replace all)

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "deploy-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

> **Warning:** `nodered-deploy` replaces **all** running flows. Use `nodered-add-flow` to add without replacing.

### Add a flow tab (non-destructive)

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "addflow-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-add-flow,$FLOWS\"}]"
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
| `MG_UI_PORT`                      | `9999`                                    | Agent UI port              |
