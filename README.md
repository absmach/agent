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

Magistrala IoT Agent is a communication, execution and software management agent for the [Magistrala][magistrala] IoT platform. It runs on edge devices and bridges local services (Node-RED, terminal) with a Magistrala deployment over MQTT. That Magistrala deployment can be local or cloud-hosted. A built-in web UI is included for local management.

## MQTT and Local Messaging

The agent uses two messaging paths:

- **MQTT** is used for the Magistrala-facing control and data plane. The agent connects to the MQTT broker from the rendered bootstrap profile or environment config, subscribes for commands on `m/<domain-id>/c/<commands-channel-id>/req`, and publishes responses on the commands channel plus data messages on the telemetry channel. This MQTT broker can be a local Magistrala deployment or Magistrala Cloud.
- **FluxMQ over AMQP** is used for local gateway service messaging. The agent subscribes to local heartbeat messages on the FluxMQ-backed message bus so nearby services can report liveness without the agent polling them.

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

The recommended way to run agent is with the provided Docker Compose stack, which also starts Node-RED, FluxMQ, and the Agent UI.

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
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<external-id>
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<external-key>
MG_AGENT_BOOTSTRAP_URL=http://bootstrap:9013/clients/bootstrap
```

You can fetch the rendered bootstrap response directly:

```bash
curl -s 'http://localhost:9013/clients/bootstrap/01:6:0:sb:sa' \
  -H 'accept: */*' \
  -H 'Authorization: Client secret'
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
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<external-id> \
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<external-key> \
MG_AGENT_BOOTSTRAP_URL=http://localhost:9013/clients/bootstrap \
build/magistrala-agent
```

### Config

In the normal runtime flow, configuration is built from environment variables plus the rendered bootstrap profile. Environment variables provide local infrastructure settings, such as HTTP port, FluxMQ URL, Node-RED URL, MQTT TLS options, and bootstrap credentials. The rendered bootstrap profile provides device identity, domain ID, MQTT credentials, and telemetry/commands channel IDs.

The legacy `config.toml` fallback still exists for local development, but bootstrap mode skips reading the file when `MG_AGENT_BOOTSTRAP_URL`, `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`, and `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` are all set.

Environment variables:

| Variable                                 | Description                                            | Default                              |
| ---------------------------------------- | ------------------------------------------------------ | ------------------------------------ |
| `MG_AGENT_CONFIG_FILE`                   | Legacy fallback config file, ignored in bootstrap mode | `config.toml`                        |
| `MG_AGENT_LOG_LEVEL`                     | Log level                                              | `info`                               |
| `MG_AGENT_HTTP_PORT`                     | Agent HTTP port                                        | `9999`                               |
| `MG_AGENT_PORT`                          | Alias for agent HTTP port                              |                                      |
| `MG_AGENT_BROKER_URL`                    | FluxMQ (AMQP) broker URL                               | `amqp://guest:guest@localhost:5682/` |
| `MG_AGENT_MQTT_URL`                      | MQTT broker URL                                        | `localhost:1883`                     |
| `MG_AGENT_MQTT_SKIP_TLS`                 | Skip TLS verification for MQTT                         | `true`                               |
| `MG_AGENT_MQTT_MTLS`                     | Use mTLS for MQTT                                      | `false`                              |
| `MG_AGENT_MQTT_CA`                       | CA certificate path for mTLS                           | `ca.crt`                             |
| `MG_AGENT_MQTT_CLIENT_CERT`              | Client certificate path for mTLS                       | `client.cert`                        |
| `MG_AGENT_MQTT_CLIENT_KEY`               | Client private key path for mTLS                       | `client.key`                         |
| `MG_AGENT_MQTT_QOS`                      | MQTT QoS level                                         | `0`                                  |
| `MG_AGENT_MQTT_RETAIN`                   | MQTT retain flag                                       | `false`                              |
| `MG_AGENT_NODERED_URL`                   | Node-RED API URL                                       | `http://localhost:1880/`             |
| `MG_AGENT_HEARTBEAT_INTERVAL`            | Expected heartbeat interval                            | `10s`                                |
| `MG_AGENT_TERMINAL_SESSION_TIMEOUT`      | Terminal session timeout                               | `60s`                                |
| `MG_AGENT_BOOTSTRAP_URL`                 | Bootstrap base URL                                     |                                      |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`         | Bootstrap external ID                                  |                                      |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY`        | Bootstrap external key                                 |                                      |
| `MG_AGENT_BOOTSTRAP_RETRIES`             | Bootstrap fetch retries                                | `5`                                  |
| `MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS` | Bootstrap retry delay in seconds                       | `10`                                 |
| `MG_AGENT_BOOTSTRAP_SKIP_TLS`            | Skip TLS verification for bootstrap fetch              | `false`                              |
| `MG_AGENT_CLIENTS_URL`                   | Magistrala Clients API URL for device provisioning     |                                      |
| `MG_AGENT_CHANNELS_URL`                  | Magistrala Channels API URL for device provisioning    |                                      |
| `MG_AGENT_RULES_ENGINE_URL`              | Magistrala Rules Engine URL (optional, for save_senml) |                                      |
| `MG_PAT`                                 | Magistrala Personal Access Token for provisioning      |                                      |
| `MG_AGENT_DEVICE_DB_PATH`                | BoltDB file path for the device registry               | `/var/lib/agent/devices.db`          |

## MQTT Message Format

Agent uses MQTT against the configured Magistrala MQTT broker. It subscribes to `m/<domain-id>/c/<commands-channel-id>/req`.

All messages use [SenML][senml] JSON array format:

```json
[{ "bn": "<uuid>:", "n": "<subsystem>", "vs": "<command>[,<args>]" }]
```

The `n` field selects the subsystem. Supported subsystems:

| `n`       | Description                                       |
| --------- | ------------------------------------------------- |
| `control` | Node-RED commands                                 |
| `exec`    | Execute a shell command                           |
| `config`  | View runtime config or save export service config |
| `term`    | Terminal session control                          |
| `nodered` | Node-RED flow management                          |
| `devices` | Downstream device registry management             |

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

Agent can manage Node-RED flows running on the same device. Flows can be deployed either via the Node-RED UI directly, via the agent's HTTP API (local), or from Magistrala over MQTT.

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

### Via MQTT (from Magistrala)

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

## Device Manager

The agent maintains a registry of downstream devices (Serial/Modbus, I2C, BLE, USB CDC) backed by a persistent BoltDB file. Each device is provisioned as a Magistrala Client and Channel pair, enabling it to publish telemetry independently through the gateway's MQTT connection.

### Configuration

| Variable                    | Description                                            | Default                     |
| --------------------------- | ------------------------------------------------------ | --------------------------- |
| `MG_AGENT_CLIENTS_URL`      | Magistrala Clients API base URL                        |                             |
| `MG_AGENT_CHANNELS_URL`     | Magistrala Channels API base URL                       |                             |
| `MG_AGENT_RULES_ENGINE_URL` | Magistrala Rules Engine URL (creates `save_senml` rule)|                             |
| `MG_PAT`                    | Magistrala Personal Access Token                       |                             |
| `MG_AGENT_DEVICE_DB_PATH`   | BoltDB path for the device registry                    | `/var/lib/agent/devices.db` |

When `MG_PAT` is set via bootstrap config, it is stored in the config store and does not need to be set as an env var on subsequent restarts.

### REST API

#### Add a device

Provisions a new Magistrala Client + Channel for the device and persists it to the registry. The returned `id` and `key` are the device's Magistrala credentials.

```bash
curl -s -X POST http://localhost:9999/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "name":           "temperature-sensor-01",
    "ext_id":         "sensor-hw-id-001",
    "ext_key":        "sensor-hw-secret-001",
    "interface_type": "serial",
    "interface_addr": "/dev/ttyUSB0"
  }'
```

Supported `interface_type` values: `serial`, `i2c`, `ble`, `usb`, `modbus_rtu`, `modbus_tcp`.

Response (`201 Created`):

```json
{
  "id":             "<magistrala-client-id>",
  "key":            "<magistrala-client-secret>",
  "channel_id":     "<magistrala-channel-id>",
  "name":           "temperature-sensor-01",
  "interface_type": "serial",
  "interface_addr": "/dev/ttyUSB0",
  "active":         false,
  "last_seen":      "0001-01-01T00:00:00Z"
}
```

#### List devices

```bash
curl -s http://localhost:9999/devices
```

Response (`200 OK`):

```json
{
  "devices": [
    {
      "id":             "<magistrala-client-id>",
      "key":            "<magistrala-client-secret>",
      "channel_id":     "<magistrala-channel-id>",
      "name":           "temperature-sensor-01",
      "interface_type": "serial",
      "interface_addr": "/dev/ttyUSB0",
      "active":         true,
      "last_seen":      "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### Get a device

```bash
curl -s http://localhost:9999/devices/<device-id>
```

#### Remove a device

```bash
curl -s -X DELETE http://localhost:9999/devices/<device-id>
```

Stops the device telemetry goroutine and removes the device from the local registry. The Magistrala Client and Channel are **not** deleted from Magistrala.

#### Mark device seen

Manually update the `last_seen` timestamp (useful for devices that communicate out-of-band):

```bash
curl -s -X POST http://localhost:9999/devices/<device-id>/seen
```

### MQTT Commands (via Magistrala)

The `devices` subsystem is invoked via `n: "devices"` on the commands channel. The `vs` field carries a subcommand, optionally followed by a comma-separated argument or a JSON payload.

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"devices", "vs":"<subcommand>[,<args>]"}]'
```

Supported subcommands:

| Subcommand | `vs` format | Description |
| ---------- | ----------- | ----------- |
| `list` | `list` | Return JSON array of all devices |
| `get` | `get,<device-id>` | Return JSON for one device |
| `add` | `add,{"name":"...","external_id":"...","external_key":"...","iface_type":"...","iface_addr":"..."}` | Provision and register a device |
| `remove` | `remove,<device-id>` | Deregister a device |
| `seen` | `seen,<device-id>` | Mark device last-seen |
| `open` | `open,<device-id>` | Open the physical interface |
| `close` | `close,<device-id>` | Close the physical interface |
| `read` | `read,<device-id>,<n-bytes>` | Read n bytes from interface (reply as hex) |
| `write` | `write,<device-id>,<hex-data>` | Write hex bytes to interface |

Responses are published to `m/<domain-id>/c/<commands-channel-id>/res`.

### Telemetry Scheduling

Once registered, each device with a non-empty `channel_id` gets a dedicated telemetry goroutine. The goroutine:

1. Opens a separate MQTT connection authenticated as the device (using its Magistrala `id`/`key`).
2. Opens the physical interface (`/dev/ttyUSB0`, I2C bus, etc.).
3. Reads bytes from the interface and publishes raw payloads to `m/<domain-id>/c/<device-channel-id>/msg`.
4. Marks the device as `active` and updates `last_seen` after each successful publish.

The goroutine reconnects with exponential backoff (1 s → 30 s) after any failure. Goroutines are restored from the persistent registry on agent restart, so devices survive process restarts without re-provisioning.

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

Agent can push an export service config file from Magistrala to the gateway via MQTT. Bootstrap mode does not update the agent runtime config this way.

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
