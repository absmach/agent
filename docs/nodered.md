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

This starts: Agent (:9999), Node-RED (:1880), FluxMQ (:5682), Agent UI (:3002).

### 3. Verify services

```bash
# Check agent health
curl http://localhost:9999/health

# Ping Node-RED via agent
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-ping"}'

# Open the Agent UI
open http://localhost:3002

# Open Node-RED UI
open http://localhost:1880
```

## Provisioning with Magistrala

If you have a running Magistrala instance, use the provisioning script to automatically create Clients, Channels, and Rule Engine rules:

```bash
export MG_PAT=<personal-access-token>
export MG_DOMAIN_ID=<domain-id>
make run_provision
```

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
MG_API=https://my-instance/api make run_provision MG_DOMAIN_ID=<domain-id> MG_PAT=<pat>
```

For Magistrala Cloud specifically, use:

```bash
MG_API=https://cloud.magistrala.absmach.eu/api \
MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883 \
MG_AGENT_MQTT_SKIP_TLS=false \
make run_provision MG_DOMAIN_ID=<domain-id> MG_PAT=<pat>
```

That combination targets the cloud APIs for provisioning and the cloud MQTT broker for runtime messaging.

Or run the script directly:

```bash
export MG_PAT=<personal-access-token>
export MG_DOMAIN_ID=<domain-id>
bash scripts/provision.sh
```

This will:
1. Create a Client (device) with credentials
2. Create a Channel
3. Create a Bootstrap configuration with `external_id`, `external_key`, channel association, and the agent runtime config
4. Configure a Rule Engine rule with `save_senml` output for the `data` subtopic
5. Update `configs/config.toml` with the provisioned IDs and MQTT credentials

**Alternatively**, if you prefer to set up resources manually via the Magistrala UI or API, simply edit `docker/.env` directly with your values:

```env
MG_AGENT_MQTT_URL=ssl://messaging.example.com:8883
MG_AGENT_CLIENT_ID=<client-id>
MG_AGENT_CLIENT_SECRET=<client-secret>
MG_AGENT_DOMAIN_ID=<domain-id>
MG_AGENT_CHANNEL=<channel-id>
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

Send a SenML array to `m/<domain-id>/c/<channel-id>/req`:

Supported commands:
- `nodered-deploy,<base64-flow>` — **Replace all running flows** with the provided flow JSON
- `nodered-add-flow,<base64-flow>` — **Add a new flow tab** alongside existing running flows
- `nodered-flows` — Fetch current flows
- `nodered-state` — Get runtime state
- `nodered-ping` — Check Node-RED availability

### Via Control command

```json
[{"bn":"uuid:", "n":"control", "vs":"nodered-deploy,<base64-encoded-flow-json>"}]
```

## Example Flows

### Default flow (`docker/nodered/flows.json`)

Seeded into Node-RED on first start. It periodically publishes SenML temperature and humidity readings to the Magistrala data channel.

### Speed sensor flow (`examples/nodered/speed-flow.json`)

A ready-to-deploy example that publishes `speed` (km/h), `rpm`, and `gear` SenML records every 15 seconds. Use it to test remote flow deployment end-to-end.

### Modbus holding register flow (`examples/nodered/modbus-flow.json`)

Simulates polling 4 Modbus TCP holding registers (FC03) every 10 seconds and publishing SenML records to Magistrala:

| Register | Measurement | Unit |
|----------|-------------|------|
| HR0 | Voltage | V |
| HR1 | Current (scaled ×10) | A |
| HR2 | Power | W |
| HR3 | Temperature | °C |

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
  -t "m/<domain-id>/c/<channel-id>/req" \
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
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m '[{"bn":"req-2:", "n":"nodered", "vs":"nodered-flows"}]'
```

The agent logs will show:
```json
{"level":"INFO","msg":"NodeRed command \"nodered-deploy,...\" completed successfully.","duration":"...","uuid":"req-1"}
```

Node-RED will start publishing speed data to `m/<domain-id>/c/<channel-id>/data` within 3 seconds of deployment.

## Configuration

The Node-RED URL is configured via:

- **Environment variable**: `MG_AGENT_NODERED_URL` (default: `http://localhost:1880/`)
- **Config file** (`config.toml`):
  ```toml
  [nodered]
    url = "http://localhost:1880/"
  ```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MG_AGENT_NODERED_URL` | `http://localhost:1880/` | Node-RED REST API base URL |
| `MG_AGENT_CLIENT_ID` | (pre-set UUID) | Magistrala Client ID |
| `MG_AGENT_CLIENT_SECRET` | (pre-set UUID) | Magistrala Client Secret |
| `MG_AGENT_CHANNEL` | (pre-set UUID) | Channel ID (req/data/res subtopics) |
| `MG_UI_PORT` | `3002` | Agent UI port |
