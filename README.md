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

If you have a running Magistrala instance, provision the required client, channels, bootstrap profile/enrollment, profile bindings, and `save_senml` rule.

Export the provisioning values first:

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID='01:6:0:sb:sa'
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY='secret'
export MG_DOMAIN_ID=<domain-id>
export MG_PAT=<personal-access-token>
make run_provision
```

Use your real PAT in the shell, but do not commit it to files. The provisioning script no longer writes a runtime `config.toml`; it creates a Bootstrap Profile and Enrollment. At startup, the agent and Node-RED fetch the rendered bootstrap profile and use that as the runtime config source.

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
export MG_DOMAIN_ID=<domain-id>
export MG_PAT=<personal-access-token>
export MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883
export MG_AGENT_MQTT_SKIP_TLS=false
make run_provision
```

Using `MG_API=https://cloud.magistrala.absmach.eu/api` points provisioning at Magistrala Cloud. Setting `MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883` points the agent at the cloud MQTT broker instead of the local Docker default.

**Alternatively**, create a Client, telemetry Channel, commands Channel, Bootstrap Profile, Enrollment, profile bindings, and Rule Engine rule manually via the Magistrala UI or API, then set bootstrap runtime env vars in `docker/.env`.

For bootstrap mode, the runtime env values are:

```env
MG_AGENT_BOOTSTRAP_ID=<external-id>
MG_AGENT_BOOTSTRAP_KEY=<external-key>
MG_AGENT_BOOTSTRAP_URL=http://bootstrap:9013/clients/bootstrap
```

You can fetch the rendered bootstrap response directly:

```bash
postman request 'http://localhost:9013/clients/bootstrap/01:6:0:sb:sa' \
  --header 'accept: */*' \
  --header 'Authorization: Client secret'
```

The bootstrap endpoint returns a wrapper object. The agent parses the JSON string in `content`:

```json
{
  "content": "{\"device_id\":\"<client-id>\",\"external_id\":\"01:6:0:sb:sa\",\"domain_id\":\"<domain-id>\",\"mqtt\":{\"url\":\"ssl://host.docker.internal:8883\",\"client_id\":\"<client-id>\",\"secret\":\"<client-secret>\"},\"telemetry\":{\"channel_id\":\"<telemetry-channel-id>\",\"topic\":\"m/<domain-id>/c/<telemetry-channel-id>/msg\"},\"commands\":{\"channel_id\":\"<commands-channel-id>\"}}",
  "client_key": "",
  "client_cert": "",
  "ca_cert": ""
}
```

Decoded, the rendered profile content looks like:

```json
{
  "device_id": "<client-id>",
  "external_id": "01:6:0:sb:sa",
  "domain_id": "<domain-id>",
  "mqtt": {
    "url": "ssl://host.docker.internal:8883",
    "client_id": "<client-id>",
    "secret": "<client-secret>"
  },
  "telemetry": {
    "channel_id": "<telemetry-channel-id>",
    "topic": "m/<domain-id>/c/<telemetry-channel-id>/msg"
  },
  "commands": {
    "channel_id": "<commands-channel-id>"
  }
}
```

### 2. Build the dev Docker image

```bash
make all && make dockers_dev
```

### 3. Start the stack

```bash
make run
```

Starts: Agent (:9999), Node-RED (:1880), Agent UI (:3002).

### Stopping

```bash
make stop
make clean_volumes
```

## Agent UI

A web-based management UI is included and served at `http://localhost:3002`. It provides:

- **Configuration** — view the effective runtime config (`server`, `channels`, `mqtt`, `nodered`, `log`)
- **Node-RED** — ping, get state, fetch flows, deploy flows (replaces all running flows), and add a single flow tab (non-destructive) from a local JSON file
- **Services** — view registered heartbeat services
- **Execute Command** — run shell commands on the edge device and see terminal-style output

The UI is built with [Elm](https://elm-lang.org/) and served via nginx as a Docker container.

To build the UI image:

```bash
make dockers_dev
```

## Running without Docker

Start FluxMQ (or use an existing Magistrala FluxMQ instance), then run the agent with bootstrap env vars:

```bash
MG_AGENT_BOOTSTRAP_ID=<external-id> \
MG_AGENT_BOOTSTRAP_KEY=<external-key> \
MG_AGENT_BOOTSTRAP_URL=http://localhost:9013/clients/bootstrap \
build/magistrala-agent
```

### Config

In the normal runtime flow, configuration is built from environment variables plus the rendered bootstrap profile. Environment variables provide local infrastructure settings, such as HTTP port, FluxMQ URL, Node-RED URL, MQTT TLS options, and bootstrap credentials. The rendered bootstrap profile provides device identity, domain ID, MQTT credentials, and telemetry/commands channel IDs.

The legacy `config.toml` fallback still exists for local development, but bootstrap mode skips reading the file when `MG_AGENT_BOOTSTRAP_URL`, `MG_AGENT_BOOTSTRAP_ID`, or `MG_AGENT_BOOTSTRAP_KEY` is set.

Environment variables:

| Variable | Description | Default |
|---|---|---|
| `MG_AGENT_CONFIG_FILE` | Legacy fallback config file, ignored in bootstrap mode | `config.toml` |
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

Agent subscribes to `m/<domain-id>/c/<commands-channel-id>/req`.

All messages use [SenML][senml] JSON array format:

```json
[{"bn": "<uuid>:", "n": "<subsystem>", "vs": "<command>[,<args>]"}]
```

The `n` field selects the subsystem. Supported subsystems:

| `n` | Description |
|---|---|
| `control` | Node-RED commands |
| `exec` | Execute a shell command |
| `config` | View runtime config or save export service config |
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
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"pwd"}]'

# With arguments
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'
```

Commands are executed via `sh -c` so shell builtins and pipelines are supported. Each invocation is stateless; use `&&` to chain commands: `ls,-la,/tmp,&&,cat,/etc/os-release`.

### View service config

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"view"}]'
```

Responses are published to `m/<domain-id>/c/<commands-channel-id>/res`.

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
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
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

## How to Save Export Config via Agent

Agent can push an export service config file from cloud to gateway via MQTT. Bootstrap mode does not update the agent runtime config this way.

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"req-1:\", \"n\":\"config\", \"vs\":\"<config_file_path>,<file_content_base64>\"}]"
```

Generate the base64 payload from a JSON export config file:

```bash
base64 -w 0 export.json
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
