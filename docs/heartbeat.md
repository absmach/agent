# Heartbeat

The heartbeat subsystem tracks liveness of both the agent itself and services running on the same host.

## Overview

Two heartbeat paths exist:

| Path                  | Transport             | Purpose                                                         |
| --------------------- | --------------------- | --------------------------------------------------------------- |
| **Self-heartbeat**    | MQTT → Magistrala     | Agent publishes its own status periodically                     |
| **Service heartbeat** | FluxMQ (AMQP) → local | Co-located services register liveness via the local message bus |

The agent also accepts an MQTT `ping` command that publishes an immediate heartbeat without waiting for the next interval.

## Self-Heartbeat

The agent publishes a SenML heartbeat to the telemetry channel on startup and at every interval:

**Topic:** `m/<domain-id>/c/<telemetry-channel-id>/gateway/heartbeat`

**Payload schema:**

```json
[
  { "bn": "agent:", "n": "service_type", "vs": "agent" },
  { "n": "heartbeat", "vb": true },
  { "n": "fw_version", "vs": "0.0.0" },
  { "n": "uptime", "u": "s", "v": 123.4 },
  { "n": "heap_free", "u": "By", "v": 1048576 },
  { "n": "devices", "u": "count", "v": 3 },
  { "n": "connected", "vb": true }
]
```

| Field          | Type   | Unit    | Description                               |
| -------------- | ------ | ------- | ----------------------------------------- |
| `service_type` | string | —       | Always `"agent"`                          |
| `heartbeat`    | bool   | —       | Always `true`                             |
| `fw_version`   | string | —       | Agent binary version (set via `-ldflags`) |
| `uptime`       | float  | `s`     | Seconds since agent started               |
| `heap_free`    | float  | `By`    | Go runtime free heap bytes                |
| `devices`      | float  | `count` | Number of registered downstream devices   |
| `connected`    | bool   | —       | MQTT connection state                     |

## Service Heartbeat

Co-located services publish a heartbeat message to the local FluxMQ broker. The agent subscribes to `m/<domain-id>/c/<commands-channel-id>/services/#` and extracts the service name and type from the topic path.

**Topic format:** `heartbeat.<service-name>.<service-type>`

When a heartbeat is received, the agent:

1. Creates a tracker entry if the service is new
2. Resets the service's `last_seen` timestamp
3. Marks the service as `online`

If no heartbeat arrives within the configured interval, the service is marked `offline`.

**Service info schema:**

```json
{
  "name": "myservice",
  "last_seen": "2026-06-10T12:00:00Z",
  "status": "online",
  "type": "sensor",
  "terminal": 0
}
```

## Configuration

### Environment Variables

| Variable                      | Default                              | Description                                                                          |
| ----------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------ |
| `MG_AGENT_HEARTBEAT_INTERVAL` | `10s`                                | Period between self-heartbeat publishes and the timeout for marking services offline |
| `MG_AGENT_BROKER_URL`         | `amqp://guest:guest@localhost:5682/` | FluxMQ (AMQP) broker URL for local service heartbeats                                |

### Runtime Config (MQTT set)

The heartbeat interval can be changed at runtime via the `config` subsystem:

```
config set heartbeat_interval <duration>
```

See [control.md](control.md) for the full `config set` recipe.

## Topic Map

| Direction       | Topic                                           | QoS          | Description                          |
| --------------- | ----------------------------------------------- | ------------ | ------------------------------------ |
| Agent → Cloud   | `m/<domain-id>/c/<data-chan>/gateway/heartbeat` | Configurable | Periodic self-heartbeat              |
| Service → Agent | `heartbeat.<name>.<type>` (via AMQP)            | —            | Local service registration           |
| Cloud → Agent   | `m/<domain-id>/c/<ctrl-chan>/req`               | 1            | `ping` command (on-demand heartbeat) |

## MQTT Test Recipes

### Subscribe to self-heartbeat

```bash
mosquitto_sub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<telemetry-channel-id>/gateway/heartbeat" \
  -v
```

**Expected output (repeats every interval):**

```
m/<domain-id>/c/<telemetry-channel-id>/gateway/heartbeat [{"bn":"agent:","n":"service_type","vs":"agent","t":...},{"n":"heartbeat","vb":true,"t":...},{"n":"fw_version","vs":"0.0.0","t":...},{"n":"uptime","u":"s","v":42.5,"t":...},{"n":"heap_free","u":"By","v":...,"t":...},{"n":"devices","u":"count","v":0,"t":...},{"n":"connected","vb":true,"t":...}]
```

### Trigger an on-demand ping

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "ping-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"ping", "vs":""}]'
```

### Check registered services via HTTP

```bash
curl -s http://localhost:9999/services | jq .
```

**Expected output:**

```json
[
  {
    "name": "myservice",
    "last_seen": "2026-06-10T12:00:00Z",
    "status": "online",
    "type": "sensor",
    "terminal": 0
  }
]
```

### Publish a local service heartbeat (Go)

```bash
go run ./examples/publish/main.go \
  -s amqp://guest:guest@localhost:5682/ \
  heartbeat.myservice.sensor ""
```

### Change heartbeat interval at runtime

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,heartbeat_interval,30s"}]'
```

The agent responds on the control response topic with `"ok"` and the next heartbeat uses the new interval.

## Troubleshooting

| Symptom                                                   | Cause                               | Fix                                                                             |
| --------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------- |
| No heartbeat messages on telemetry topic                  | MQTT not connected                  | Check `connected` field via `/services`; verify MQTT credentials and broker URL |
| Service stuck in `offline`                                | Service not publishing to FluxMQ    | Ensure service publishes to `heartbeat.<name>.<type>` on the AMQP broker        |
| `ping` command has no response                            | Wrong topic or missing SenML format | Verify the request topic is `m/<domain-id>/c/<ctrl-chan>/req`                   |
| Heartbeat interval change has no effect                   | Invalid duration string             | Use Go duration format: `30s`, `1m`, etc. (minimum `1s`)                        |
| Agent logs `"failed to count devices for self-heartbeat"` | Device DB error                     | Check `MG_AGENT_DEVICE_DB_PATH` permissions                                     |
