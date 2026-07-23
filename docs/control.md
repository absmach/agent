# Remote Control

Remote control is JSON-RPC 2.0 over MQTT 5. The old SenML command dispatcher is
not subscribed to `/req` and is not part of the remote contract.

## Topics

```text
Request:  m/{domain}/c/{controlChannel}/req
Response: m/{domain}/c/{controlChannel}/res/{requesterId}
```

The control channel must be dedicated to one Agent. The Agent validates MQTT
Response Topic, Correlation Data, content type, API version, message expiry and
application deadline before dispatching a method.

## Example request

```json
{
  "jsonrpc": "2.0",
  "id": "a10aaea7-66bd-4b88-a6e7-c3852c62cb24",
  "method": "runtimeConfig.set",
  "params": {
    "key": "telemetry_interval",
    "value": "30s",
    "expectedRevision": 4
  }
}
```

Mutating operations are deduplicated by UUID. Configuration mutations can use
`expectedRevision` to reject stale writes.

## Method groups

```text
system.*
agent.*
config.*
runtimeConfig.*
service.*
device.*
backup.*
nodeRed.*
firmware.*
job.*
log.stream.*
terminal.*
stream.*
```

The complete parameters, results, roles, expiry and idempotency classifications
are in [`api/openrpc.json`](../api/openrpc.json).

The local UI continues to use GoKit HTTP endpoints. Both transports call the
same `agent.Service`; the remote implementation is not a second copy of the
business logic.

See:

- [remote-protocol.md](remote-protocol.md)
- [mqtt-acl.md](mqtt-acl.md)
- [`api/asyncapi.yaml`](../api/asyncapi.yaml)
