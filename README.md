# Magistrala IoT Agent

![badge](https://github.com/absmach/agent/workflows/Go/badge.svg)
![ci][ci]
![release][release]
[![go report card][grc-badge]][grc-url]
[![license][license]](LICENSE)
[![chat][gitter-badge]][gitter]

<p align="center">
  <img width="30%" height="30%" src="./docs/img/agent.png">
</p>

Magistrala IoT Agent is a communication, execution and software management agent for the [Magistrala][magistrala] IoT platform. It runs on edge devices and bridges local services (Node-RED, terminal) with the Magistrala cloud over MQTT.

## Install

```bash
git clone https://github.com/absmach/agent
cd agent
```

Build the binary:

```bash
make all
```

The binary is written to `build/magistrala-agent`.

## Running with Docker

The recommended way to run agent is with the provided Docker Compose stack, which also starts Node-RED, FluxMQ, and Mosquitto.

### 1. Provision Magistrala resources

If you have a running Magistrala instance, create the required clients and channels:

```bash
export MG_PAT=<personal-access-token>
export MG_DOMAIN_ID=<domain-id>
make run_provision
```

This creates the necessary Magistrala clients and channels, then writes the resulting IDs and configuration into `docker/.env`.

### 2. Build the dev Docker image

```bash
make all && make docker_dev
```

### 3. Start the stack

```bash
make run
```

Starts: Agent (:9999), Node-RED (:1880).

### Stopping

```bash
make stop
make clean_volumes
```

## Running without Docker

Start FluxMQ (or use an existing Magistrala FluxMQ instance).

Start agent with environment variables:

```bash
MG_AGENT_MQTT_URL=mqtts://messaging.example.com:8883 \
MG_AGENT_MQTT_USERNAME=<client-id> \
MG_AGENT_MQTT_PASSWORD=<client-secret> \
MG_AGENT_CHANNEL=<channel-id> \
MG_AGENT_DOMAIN_ID=<domain-id> \
build/magistrala-agent
```

### Config

Agent configuration is kept in `config.toml` if not otherwise specified with env var.

Example configuration:

```toml
[server]
  port = "9999"
  broker_url = "amqp://guest:guest@localhost:5682/"

[channels]
  id = "<channel-id>"

[mqtt]
  url      = "mqtts://messaging.example.com:8883"
  username = "<client-id>"
  password = "<client-secret>"
  qos      = 0
  retain   = false
  mtls     = false

[nodered]
  url = "http://localhost:1880/"

[log]
  level = "info"
```

Environment variables:

| Variable | Description | Default |
|---|---|---|
| `MG_AGENT_CONFIG_FILE` | Location of configuration file | `config.toml` |
| `MG_AGENT_LOG_LEVEL` | Log level | `info` |
| `MG_AGENT_HTTP_PORT` | Agent HTTP port | `9999` |
| `MG_AGENT_BROKER_URL` | FluxMQ (AMQP) broker URL | `amqp://guest:guest@localhost:5682/` |
| `MG_AGENT_MQTT_URL` | MQTT broker URL | `localhost:1883` |
| `MG_AGENT_MQTT_USERNAME` | MQTT username (Magistrala client ID) | |
| `MG_AGENT_MQTT_PASSWORD` | MQTT password (Magistrala client secret) | |
| `MG_AGENT_MQTT_SKIP_TLS` | Skip TLS verification for MQTT | `true` |
| `MG_AGENT_MQTT_MTLS` | Use mTLS for MQTT | `false` |
| `MG_AGENT_MQTT_CA` | CA certificate path for mTLS | `ca.crt` |
| `MG_AGENT_MQTT_QOS` | MQTT QoS level | `0` |
| `MG_AGENT_MQTT_RETAIN` | MQTT retain flag | `false` |
| `MG_AGENT_CHANNEL` | Channel ID (req/data/res subtopics) | |
| `MG_AGENT_DOMAIN_ID` | Magistrala domain ID | |

| `MG_AGENT_NODERED_URL` | Node-RED API URL | `http://localhost:1880/` |
| `MG_AGENT_HEARTBEAT_INTERVAL` | Expected heartbeat interval | `30s` |
| `MG_AGENT_TERMINAL_SESSION_TIMEOUT` | Terminal session timeout | `30s` |

## MQTT Message Format

Agent subscribes to `m/<domain-id>/c/<channel-id>/req`.

All messages use [SenML][senml] JSON array format:

```json
[{"bn": "<uuid>:", "n": "<subsystem>", "vs": "<command>[,<args>]"}]
```

The `n` field selects the subsystem. Supported subsystems:

| `n` | Description |
|---|---|
| `control` | EdgeX and Node-RED commands |
| `exec` | Execute a shell command |
| `config` | View or save agent config |
| `term` | Terminal session control |
| `nodered` | Node-RED flow management |

## Sending Commands

### Execute a shell command

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'
```

### View service config

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"view"}]'
```

Responses are published to `m/<domain-id>/c/<channel-id>/res`.

## Node-RED Integration

Agent can manage Node-RED flows running on the same device. Flows can be deployed either via the Node-RED UI directly, via the agent's HTTP API (local), or remotely from the Magistrala cloud over MQTT.

### Via HTTP (local)

First, base64-encode the flow JSON:

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)
```

Then send it to the agent. The agent decodes the flows, patches the MQTT client ID, and forwards them to Node-RED on its behalf:

```bash
curl -s -X POST http://localhost:9999/nodered \
  -H 'Content-Type: application/json' \
  -d "{\"command\":\"nodered-deploy\",\"flows\":\"$FLOWS\"}"
```

Other commands (no `flows` field needed):

```bash
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

```bash
FLOWS=$(cat examples/nodered/speed-flow.json | base64 -w 0)

mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "deploy-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m "[{\"bn\":\"req-1:\",\"n\":\"nodered\",\"vs\":\"nodered-deploy,$FLOWS\"}]"
```

In both cases `flows` is the flow JSON **base64-encoded**. The agent automatically patches the MQTT `clientid` inside the deployed flows to `<client-id>-nr` to prevent Node-RED from conflicting with the agent's own MQTT session.

See [docs/nodered.md](docs/nodered.md) for the full setup guide, Docker Compose stack, and provisioning instructions.


## Heartbeat Service

Services running on the same host can publish to `heartbeat.<service-name>.<service-type>` to register with the agent.

```bash
go run ./examples/publish/main.go -s amqp://guest:guest@localhost:5682/ heartbeat.myservice.sensor ""
```

Check registered services:

```bash
curl -s http://localhost:9999/services
```

## How to Save Config via Agent

Agent can push a config file for the [Export][export] service from cloud to gateway via MQTT:

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m "[{\"bn\":\"req-1:\", \"n\":\"config\", \"vs\":\"<config_file_path>,<file_content_base64>\"}]"
```

Generate the base64 payload:

```go
b, _ := toml.Marshal(export.Config)
payload := base64.StdEncoding.EncodeToString(b)
```

## License

[Apache-2.0](LICENSE)

[grc-badge]: https://goreportcard.com/badge/github.com/absmach/agent
[grc-url]: https://goreportcard.com/report/github.com/absmach/agent
[license]: https://img.shields.io/badge/license-Apache%20v2.0-blue.svg
[export]: https://github.com/absmach/export
[provision]: https://github.com/absmach/magistrala/tree/main/cli
[magistrala]: https://github.com/absmach/magistrala
[senml]: https://tools.ietf.org/html/rfc8428
[ci]: https://github.com/absmach/agent/actions/workflows/ci.yml/badge.svg
[release]: https://github.com/absmach/agent/actions/workflows/release.yml/badge.svg


