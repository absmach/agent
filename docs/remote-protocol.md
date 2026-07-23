# Remote MQTT 5 Protocol

The local HTTP, SSE and WebSocket API remains available for on-device use. The
remote API is a breaking replacement for the old SenML command envelope.

## Topics

Control channel:

```text
m/{domain}/c/{control}/req
m/{domain}/c/{control}/res/{requesterId}
m/{domain}/c/{control}/gateway/state/desired
m/{domain}/c/{control}/gateway/streams/{sessionId}/control
m/{domain}/c/{control}/gateway/streams/{sessionId}/in
m/{domain}/c/{control}/service/{serviceName}/req
m/{domain}/c/{control}/service/{serviceName}/res/{agentId}/{bootId}
```

Data channel:

```text
m/{domain}/c/{data}/gateway/heartbeat
m/{domain}/c/{data}/gateway/telemetry
m/{domain}/c/{data}/gateway/presence
m/{domain}/c/{data}/gateway/events
m/{domain}/c/{data}/gateway/state/reported
m/{domain}/c/{data}/gateway/jobs/events
m/{domain}/c/{data}/gateway/streams/{sessionId}/out
```

## RPC request requirements

RPC uses JSON-RPC 2.0 and MQTT 5:

| MQTT field | Requirement |
| --- | --- |
| QoS | `1` |
| Retain | `false` |
| Response Topic | `m/{domain}/c/{control}/res/{requesterId}` |
| Correlation Data | Raw 16-byte form of the JSON-RPC UUID |
| Message Expiry | Required |
| Content Type | `application/json` |
| Payload Format | UTF-8 |
| User Property | `api-version=1` |
| User Property | `request-deadline=<RFC3339Nano>` |

The Agent rejects a response topic outside its control channel, wildcard
response topics, expired requests, missing properties, non-UUID IDs and a
JSON-RPC ID that does not match Correlation Data. Requests are limited to 1 MiB
and 16 concurrent executions by default; overload returns `-32008`.

## Duplicate execution

Mutating requests are recorded in `/var/lib/agent/remote.db`.

- Same ID, method and parameters: replay the persisted response.
- Same ID with different content: return `-32002`.
- A request already running: return `-32003`.
- Completed records expire after the deduplication retention period.

The database has no migration layer during development. Delete it when making
an incompatible schema change.

## State and events

Telemetry and heartbeat are periodic. Presence is retained: the Agent publishes
`online` after connecting and configures an MQTT Last Will containing `offline`.
Both presence and reported state include the boot ID and supported capabilities.
Configuration, device, service and OTA
changes publish an event immediately and refresh the retained reported-state
snapshot. The control plane can still call `system.snapshot.get`,
`device.list`, or `service.list` when it needs an authoritative response.

Desired state is retained on the control channel and contains:

```json
{
  "schemaVersion": 1,
  "generation": 42,
  "config": {
    "telemetry_interval": "30s",
    "log_level": "info"
  }
}
```

## Jobs

Firmware, backup, restore, reset, full configuration and Node-RED deployment
return a durable job immediately. States are:

```text
queued -> running|waiting -> succeeded|failed|cancelled
```

Use `job.get`, `job.list` and `job.cancel`. State transitions are persisted and
published to the data channel. At most four jobs run concurrently, and jobs
left queued or running by an Agent restart are marked failed as interrupted.

## Streams

`log.stream.open` and `terminal.open` return a UUID and exact stream topics.
Sessions have an absolute lifetime, inactivity timeout and byte limit. Stream
sessions also enforce a maximum frame rate. Stream messages are never retained.
Terminal input/output normally uses QoS 0;
open/close/resize controls use QoS 1.

## Source of truth

[`api/openrpc.json`](../api/openrpc.json) is the method contract.
[`api/asyncapi.yaml`](../api/asyncapi.yaml) is the MQTT transport contract.
