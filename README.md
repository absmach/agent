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

## Features

- **MQTT command & control** — remote shell execution, config management, process reset over [SenML][senml] JSON via Magistrala MQTT
- **Node-RED integration** — deploy, fetch, and manage Node-RED flows over MQTT or HTTP
- **Interactive terminal** — full PTY sessions tunneled over MQTT
- **Periodic telemetry** — uptime, memory, CPU temperature, disk usage, load averages, wireless RSSI
- **Heartbeat & liveness** — self-heartbeat to Magistrala + local service tracking via AMQP
- **Downstream device management** — provision, register, and manage serial/I2C/Modbus devices
- **OTA updates** — remote binary update with SHA-256 verification
- **Health supervisor** — process watchdog with systemd integration
- **Bootstrap provisioning** — profile-based startup from Magistrala Bootstrap service

## Install

```bash
git clone https://github.com/absmach/agent
cd agent
make all
```

The binary is written to `build/magistrala-agent`.

## Quick Start with Docker

### 1. Provision Magistrala resources

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID='<external-id>'
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY='<external-key>'
export MG_DOMAIN_ID='<domain-id>'
export MG_PAT='<personal-access-token>'
make run_provision
```

The PAT must have scopes for `bootstrap:create`, `rules:create`, `clients:create`, `channels:create`, and connect permissions in the target domain. See [docs/bootstrap.md](docs/bootstrap.md) for details and cloud provisioning.

### 2. Build and start

```bash
make all && make dockers_dev
make run
```

Starts: Agent + UI (:9999), Node-RED (:1880).

### Stopping

```bash
make stop
make clean_volumes
```

## Agent UI

A web-based management UI at `http://localhost:9999` provides:

- **Configuration** — view the effective runtime config
- **Node-RED** — ping, get state, fetch/deploy/add flows from a local JSON file
- **Services** — view registered heartbeat services
- **Execute Command** — run shell commands on the edge device

## Running without Docker

```bash
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<external-id> \
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<external-key> \
MG_AGENT_BOOTSTRAP_URL=http://localhost:9013/clients/bootstrap \
build/magistrala-agent
```

## Configuration

Configuration comes from environment variables plus the rendered bootstrap profile. Environment variables provide local infrastructure settings (HTTP port, FluxMQ URL, Node-RED URL, MQTT TLS). The bootstrap profile provides device identity, MQTT credentials, and channel IDs. A persistent config store (`MG_AGENT_CONFIG_PATH`) holds runtime overrides applied via MQTT `config set`.

Key variables:

| Variable                          | Description                              | Default                              |
| --------------------------------- | ---------------------------------------- | ------------------------------------ |
| `MG_AGENT_HTTP_PORT`              | Agent HTTP port                          | `9999`                               |
| `MG_AGENT_MQTT_URL`               | MQTT broker URL                          | `localhost:1883`                     |
| `MG_AGENT_NODERED_URL`            | Node-RED API URL                         | `http://localhost:1880/`             |
| `MG_AGENT_BROKER_URL`             | FluxMQ (AMQP) broker URL                 | `amqp://guest:guest@localhost:5682/` |
| `MG_AGENT_HEARTBEAT_INTERVAL`     | Heartbeat interval                       | `10s`                                |
| `MG_AGENT_TELEMETRY_INTERVAL`     | Telemetry interval (`0s` to disable)     | `30s`                                |
| `MG_AGENT_LOG_LEVEL`              | Log level                                | `info`                               |
| `MG_AGENT_BOOTSTRAP_URL`          | Bootstrap base URL                       |                                      |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`  | Bootstrap external ID                    |                                      |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` | Bootstrap external key                   |                                      |

Per-feature env vars are documented in each feature doc below.

## Documentation

Per-feature documentation with configuration, MQTT topic maps, and copy-paste test recipes:

| Document                     | Description                                                                                                 |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [control.md](docs/control.md)     | Command dispatch, runtime config get/set/reset, token authentication, exec subsystem, test recipes          |
| [nodered.md](docs/nodered.md)     | Node-RED integration, flow deployment, provisioning, HTTP and MQTT management, test recipes                 |
| [telemetry.md](docs/telemetry.md) | Periodic uptime telemetry, payload format, runtime configuration, test recipes                              |
| [heartbeat.md](docs/heartbeat.md) | Self-heartbeat and service liveness tracking, interval configuration, test recipes                          |
| [terminal.md](docs/terminal.md)   | Interactive terminal sessions over MQTT, session lifecycle, PTY management, test recipes                    |
| [devices.md](docs/devices.md)     | Downstream device provisioning, physical interfaces, device CRUD, backup/restore, lifecycle webhooks, telemetry scheduler, test recipes |
| [bootstrap.md](docs/bootstrap.md) | Profile-based provisioning flow, environment variables, cache management, test recipes                      |
| [ota.md](docs/ota.md)             | Over-the-air binary updates, trigger payload, download/verify/replace cycle, status reporting, test recipes |
| [health.md](docs/health.md)       | Health supervisor, systemd watchdog integration, MQTT connection monitoring, health check endpoints         |

## License

[Apache-2.0](LICENSE)

[grc-badge]: https://goreportcard.com/badge/github.com/absmach/agent
[grc-url]: https://goreportcard.com/report/github.com/absmach/agent
[license]: https://img.shields.io/badge/license-Apache%20v2.0-blue.svg
[magistrala]: https://github.com/absmach/magistrala
[senml]: https://tools.ietf.org/html/rfc8428
[ci]: https://github.com/absmach/agent/actions/workflows/ci.yml/badge.svg
[release]: https://github.com/absmach/agent/actions/workflows/release.yml/badge.svg
