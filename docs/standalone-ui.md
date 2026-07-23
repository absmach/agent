# Standalone Agent UI

The standalone deployment keeps MQTT credentials outside the browser:

```text
Browser --HTTP/WebSocket--> Agent Gateway --MQTT 5--> Magistrala --MQTT 5--> Agent
```

The embedded local UI remains available on port `9999`. The standalone UI is
served by nginx on port `3001`.

The development Compose stack includes an anonymous local Mosquitto MQTT 5
broker so the complete Agent/Gateway/UI flow can be tested without an external
Magistrala deployment. It is a transport test broker, not a security example;
use the ACL and mTLS requirements below for a shared deployment. Its optional
host debug port defaults to `1884` to avoid colliding with a host broker.

## Required resources

Provision two channels for every Agent:

- a dedicated control channel;
- a dedicated data channel.

The IDs must be configured in both `docker/agent-config.json` and
`MG_AGENT_GATEWAY_AGENTS`. Do not share one control channel between Agents.

The Agent identity needs the Agent permissions in [mqtt-acl.md](mqtt-acl.md).
The Agent Gateway should use a different Magistrala identity with the inverse
permissions.

## Configuration

Important values in `docker/.env`:

```dotenv
MG_AGENT_GATEWAY_MQTT_USERNAME=<gateway-service-identity>
MG_AGENT_GATEWAY_MQTT_PASSWORD=<gateway-service-secret>
MG_AGENT_GATEWAY_TOKEN=<development-admin-token>
MG_AGENT_GATEWAY_AGENTS=[{"id":"edge-agent-1","domain_id":"...","control_channel":"...","data_channel":"..."}]
```

`MG_AGENT_GATEWAY_TOKEN` creates one development token with every role. A
role-scoped deployment should use:

```dotenv
MG_AGENT_GATEWAY_AUTH_TOKENS={"viewer-token":["viewer"],"support-token":["viewer","support"],"terminal-token":["viewer","terminal-admin"]}
```

Available roles are:

```text
viewer
operator
system-admin
configuration-admin
service-admin
device-admin
device-operator
backup-admin
node-red-admin
firmware-admin
support
terminal-admin
```

## Start

```bash
docker compose -p magistrala_agent \
  -f docker/docker-compose.yml \
  --env-file docker/.env \
  up -d --build
```

Open `http://localhost:3001/ui/`.

## Gateway API

| Endpoint | Required role | Purpose |
| --- | --- | --- |
| `GET /health` | public | Container health |
| `GET /api/agents` | `viewer` | Configured Agent registry |
| `POST /api/agents/{id}/rpc` | method-specific | Execute an OpenRPC method |
| `PUT /api/agents/{id}/state/desired` | `configuration-admin` | Publish retained desired state |
| `WS /api/agents/{id}/events` | `viewer` | Data-channel events, state, telemetry and job updates |
| `WS /api/agents/{id}/logs` | `support` | Bounded log session |
| `WS /api/agents/{id}/terminal` | `terminal-admin` | Bounded PTY session |

HTTP uses `Authorization: Bearer <token>`. WebSockets carry
`bearer.<base64url-token>` as a subprotocol so tokens do not appear in URLs or
proxy access logs.

The browser never receives MQTT usernames, passwords, certificates, response
topics or channel permissions.

## Contracts

- JSON-RPC methods: [`api/openrpc.json`](../api/openrpc.json)
- MQTT channels and messages: [`api/asyncapi.yaml`](../api/asyncapi.yaml)
- Runtime protocol: [remote-protocol.md](remote-protocol.md)
- Permissions: [mqtt-acl.md](mqtt-acl.md)

Direct firmware binary upload over MQTT was removed. Upload artifacts to an
HTTPS service and call `firmware.update.start` with the URL and SHA-256 digest.
