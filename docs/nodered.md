# Agent + Node-RED Integration

This guide explains how to run the Magistrala Agent with Node-RED support using a mock Linux device in Docker.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Mock Linux Device (Docker)                │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐  │
│  │  Agent   │──│ Node-RED │  │  NATS  │  │Mosquitto │  │
│  │ :9999    │  │  :1880   │  │ :4222  │  │  :1883   │  │
│  └────┬─────┘  └────┬─────┘  └────────┘  └────┬─────┘  │
│       │              │                         │        │
│       └──────────────┴─────────────────────────┘        │
└─────────────────────────────────────────────────────────┘
                           │
                    MQTT (channels)
                           │
              ┌────────────┴────────────┐
              │  Magistrala Platform    │
              │  (Bootstrap, RE, etc.)  │
              └─────────────────────────┘
```

- **Agent** connects to Mosquitto (MQTT) and NATS, manages Node-RED flows
- **Node-RED** processes IoT data via visual flows, publishes/subscribes via MQTT
- **Mosquitto** acts as the local MQTT broker (or bridges to Magistrala)
- **NATS** handles internal agent heartbeat/service management

## Quick Start

### 1. Build the Agent Docker image

```bash
make docker_agent
```

### 2. Start the mock device

```bash
cd docker/nodered
docker compose up -d
```

This starts: Agent (:9999), Node-RED (:1880), Mosquitto (:1883), and NATS.

### 3. Verify services

```bash
# Check agent health
curl http://localhost:9999/health

# Check Node-RED via agent
curl -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command": "nodered-ping"}'

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
FLOW=$(base64 -w0 < flows.json)
curl -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d "{\"command\": \"nodered-deploy\", \"flows\": \"${FLOW}\"}"

# Fetch current flows
curl -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d '{"command": "nodered-flows"}'
```

### Via MQTT (from Magistrala cloud)

Send a SenML message to the control channel:

```json
[{"bn":"uuid:", "n":"nodered", "vs":"nodered-deploy,<base64-encoded-flow-json>"}]
```

Supported commands:
- `nodered-deploy,<base64-flow>` — Deploy flows to Node-RED
- `nodered-flows` — Fetch current flows
- `nodered-ping` — Check Node-RED availability

### Via Control command

```json
[{"bn":"uuid:", "n":"control", "vs":"nodered-deploy,<base64-encoded-flow-json>"}]
```

## Example Flow

An example flow is provided in `docker/nodered/flows.json`. It:

1. Subscribes to all Magistrala MQTT channels
2. Processes incoming SenML messages
3. Publishes processed results back
4. Periodically injects test temperature/humidity data

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
