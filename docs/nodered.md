# Agent + Node-RED Integration

This guide explains how to run the Magistrala Agent with Node-RED support using a mock Linux device in Docker.

## Architecture

<p align="center">
  <img src="img/nodered-architecture.svg" alt="Agent + Node-RED Architecture" width="100%"/>
</p>



## Quick Start

### 1. Build the Agent Docker image

```bash
make all && make docker_dev
```

### 2. Start the stack

```bash
make run
```

This starts: Agent (:9999), Node-RED (:1880), NATS (:4222).

### 3. Verify services

```bash
# Check agent health
curl http://localhost:9999/health

# Ping Node-RED via agent
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command":"nodered-ping"}'

# Open Node-RED UI
open http://localhost:1880
```

## Provisioning with Magistrala

If you have a running Magistrala instance, use the provisioning script to automatically create Things, Channels, and Rule Engine rules:

```bash
cd docker/nodered
./provision.sh http://magistrala-host admin@example.com password123
```

This will:
1. Create a Thing (device client) with credentials
2. Create Control and Data channels
3. Connect the Thing to both channels
4. Set up Bootstrap configuration
5. Configure a Rule Engine to store messages from the data channel
6. Write a `.env` file with all the IDs

Then restart the agent:
```bash
docker compose up -d
```

## Deploying Node-RED Flows

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

Send a SenML array to `m/<domain-id>/c/<control-channel-id>/req`:

```json
[{"bn":"<uuid>:", "n":"nodered", "vs":"nodered-deploy,<base64-encoded-flow-json>"}]
```

Supported commands:
- `nodered-deploy,<base64-flow>` — Deploy flows to Node-RED
- `nodered-flows` — Fetch current flows
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

**Deploy via Magistrala MQTT:**

```bash
# 1. Encode the flow
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

# 2. Publish the deploy command
mosquitto_pub \
  -h <mqtt-host> -p 8883 \
  --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  --id "deploy-$(date +%s)" \
  -t "m/<domain-id>/c/<control-channel-id>/req" \
  -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

The agent will:
1. Receive the SenML message over MQTT
2. Base64-decode the flow JSON
3. Patch the MQTT `clientid` in the flow to `<client-id>-nr` (prevents session conflict with the agent itself)
4. `PUT` the flows to Node-RED's REST API
5. Publish the result back to the control channel

**Verify the deployment:**

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 \
  --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  --id "list-$(date +%s)" \
  -t "m/<domain-id>/c/<control-channel-id>/req" \
  -m '[{"bn":"req-2:", "n":"nodered", "vs":"nodered-flows"}]'
```

The agent logs will show:
```json
{"level":"INFO","msg":"NodeRed command \"nodered-deploy,...\" completed successfully.","duration":"...","uuid":"req-1"}
```

Node-RED will start publishing speed data to `m/<domain-id>/c/<data-channel-id>/data` within 3 seconds of deployment.

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
| `MG_AGENT_THING_ID` | (pre-set UUID) | Magistrala Thing ID |
| `MG_AGENT_THING_KEY` | (pre-set UUID) | Magistrala Thing Key |
| `MG_AGENT_CONTROL_CHANNEL` | (pre-set UUID) | Control channel ID |
| `MG_AGENT_DATA_CHANNEL` | (pre-set UUID) | Data channel ID |
