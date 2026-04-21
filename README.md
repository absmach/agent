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

Magistrala IoT Agent is a communication, execution and software management agent for the [Magistrala][magistrala] IoT platform. It runs on edge devices and bridges local services (Node-RED, terminal) with the Magistrala cloud over MQTT. A built-in web UI is included for local management.

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

If you have a running Magistrala instance, provision the required client, channel, bootstrap config, and `save_senml` rule:

```bash
export MG_PAT=<personal-access-token>
export MG_DOMAIN_ID=<domain-id>
make run_provision
```

This writes the resulting runtime configuration into `configs/config.toml`.

The PAT used for provisioning must be able to create bootstrap configs, rules, clients, and channels in the target domain. In practice the provisioning flow expects scopes like:

- `bootstrap:create`
- `rules:create`
- `clients:create`
- `clients:view`
- `clients:connect_to_channel`
- `channels:create`
- `channels:view`
- `channels:connect_client`

all scoped to the target `domain_id`.

The provisioning script uses sensible defaults for local Docker:

- MQTT: `ssl://host.docker.internal:8883`
- Bootstrap API: `http://localhost:9013`

Override them before provisioning when needed, for example:

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<device-external-id>
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<device-external-key>
export MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883
export MG_AGENT_MQTT_SKIP_TLS=false
make run_provision
```

**Alternatively**, create a Client, Channel, Bootstrap config, and Rule Engine rule manually via the Magistrala UI or API, then update `configs/config.toml` or set bootstrap runtime env vars in `docker/.env`.

For bootstrap mode, the runtime env values are:

```env
MG_AGENT_BOOTSTRAP_ID=<external-id>
MG_AGENT_BOOTSTRAP_KEY=<external-key>
MG_AGENT_BOOTSTRAP_URL=http://bootstrap:9013/clients/bootstrap
```

### 2. Build the dev Docker image

```bash
make all && make dockers_dev
```

### 3. Start the stack

```bash
make run
```

Starts: Agent (:9999), Node-RED (:1880), Agent UI (:3000).

### Stopping

```bash
make stop
make clean_volumes
```

## Agent UI

A web-based management UI is included and served at `http://localhost:3000`. It provides:

- **Configuration** — view and save the agent config (`server`, `channels`, `mqtt`, `nodered`, `log`)
- **Node-RED** — ping, get state, fetch flows, deploy flows (replaces all running flows), and add a single flow tab (non-destructive) from a local JSON file
- **Services** — view registered heartbeat services
- **Execute Command** — run shell commands on the edge device and see terminal-style output

The UI is built with [Elm](https://elm-lang.org/) and served via nginx as a Docker container.

To build the UI image:

```bash
make dockers_dev
```

## Running without Docker

Start FluxMQ (or use an existing Magistrala FluxMQ instance), then provide a valid `config.toml` or bootstrap env vars.

Start agent with a config file:

```bash
MG_AGENT_CONFIG_FILE=configs/config.toml build/magistrala-agent
```

Or via bootstrap:

```bash
MG_AGENT_BOOTSTRAP_ID=<external-id> \
MG_AGENT_BOOTSTRAP_KEY=<external-key> \
MG_AGENT_BOOTSTRAP_URL=http://localhost:9013/clients/bootstrap \
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
| `MG_AGENT_PORT` | Alias for agent HTTP port | |
| `MG_AGENT_BROKER_URL` | FluxMQ (AMQP) broker URL | `amqp://guest:guest@localhost:5682/` |
| `MG_AGENT_MQTT_URL` | MQTT broker URL | `localhost:1883` |
| `MG_AGENT_MQTT_SKIP_TLS` | Skip TLS verification for MQTT | `true` |
| `MG_AGENT_MQTT_MTLS` | Use mTLS for MQTT | `false` |
| `MG_AGENT_MQTT_CA` | CA certificate path for mTLS | `ca.crt` |
| `MG_AGENT_MQTT_CLIENT_CERT` | Client certificate path for mTLS | `client.cert` |
| `MG_AGENT_MQTT_CLIENT_KEY` | Client private key path for mTLS | `client.key` |
| `MG_AGENT_MQTT_QOS` | MQTT QoS level | `0` |
| `MG_AGENT_MQTT_RETAIN` | MQTT retain flag | `false` |
| `MG_AGENT_NODERED_URL` | Node-RED API URL | `http://localhost:1880/` |
| `MG_AGENT_HEARTBEAT_INTERVAL` | Expected heartbeat interval | `10s` |
| `MG_AGENT_TERMINAL_SESSION_TIMEOUT` | Terminal session timeout | `60s` |
| `MG_AGENT_BOOTSTRAP_URL` | Bootstrap base URL | |
| `MG_AGENT_BOOTSTRAP_ID` | Bootstrap external ID | |
| `MG_AGENT_BOOTSTRAP_KEY` | Bootstrap external key | |
| `MG_AGENT_BOOTSTRAP_RETRIES` | Bootstrap fetch retries | `5` |
| `MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS` | Bootstrap retry delay in seconds | `10` |
| `MG_AGENT_BOOTSTRAP_SKIP_TLS` | Skip TLS verification for bootstrap fetch | `false` |

## MQTT Message Format

Agent subscribes to `m/<domain-id>/c/<channel-id>/req`.

All messages use [SenML][senml] JSON array format:

```json
[{"bn": "<uuid>:", "n": "<subsystem>", "vs": "<command>[,<args>]"}]
```

The `n` field selects the subsystem. Supported subsystems:

| `n` | Description |
|---|---|
| `control` | Node-RED commands |
| `exec` | Execute a shell command |
| `config` | View or save agent config |
| `term` | Terminal session control |
| `nodered` | Node-RED flow management |

## Sending Commands

### Execute a shell command

Commands are passed as a comma-separated string: `command,arg1,arg2`. Commands with no arguments work as-is:

```bash
# No-arg command
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"pwd"}]'

# With arguments
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'
```

Commands are executed via `sh -c` so shell builtins and pipelines are supported. Each invocation is stateless; use `&&` to chain commands: `ls,-la,/tmp,&&,cat,/etc/os-release`.

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

Agent can push an export config file from cloud to gateway via MQTT:

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
[magistrala]: https://github.com/absmach/magistrala
[senml]: https://tools.ietf.org/html/rfc8428
[ci]: https://github.com/absmach/agent/actions/workflows/ci.yml/badge.svg
[release]: https://github.com/absmach/agent/actions/workflows/release.yml/badge.svg
