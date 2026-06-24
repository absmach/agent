# Device Manager — Downstream Device Provisioning and Management

The device manager subsystem allows the agent to provision, register, and manage downstream devices connected via physical interfaces (serial, I2C, Modbus RTU/TCP, USB). Each device is provisioned as an Atom resource with its own channel, and data from the device is forwarded to Atom over MQTT.

## Supported Interface Types

| Type         | Address Format     | Description             |
| ------------ | ------------------ | ----------------------- |
| `serial`     | `/dev/ttyS0`       | Serial / RS-232         |
| `usb`        | `/dev/ttyACM0`     | USB serial              |
| `modbus-rtu` | `/dev/ttyS0`       | Modbus RTU over serial  |
| `modbus-tcp` | `192.168.1.10:502` | Modbus TCP over network |
| `i2c`        | `/dev/i2c-1`       | Linux I2C bus           |
| `ble`        | —                  | Not yet implemented     |
| `zigbee`     | —                  | Not yet implemented     |

## Subcommands

All device commands are sent via the `devices` dispatch name on the commands channel:

| Subcommand | Format                                                                                                  | Description                                   |
| ---------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `list`     | `devices,list`                                                                                          | Returns JSON array of all registered devices  |
| `add`      | `devices,{"name":"...","external_id":"...","external_key":"...","iface_type":"...","iface_addr":"..."}` | Provision and register a new device           |
| `remove`   | `devices,remove,<device_id>`                                                                            | Deregister and remove a device                |
| `get`      | `devices,get,<device_id>`                                                                               | Returns JSON for one device                   |
| `seen`     | `devices,seen,<device_id>`                                                                              | Mark device as active / update last-seen time |
| `open`     | `devices,open,<device_id>`                                                                              | Open the physical interface for the device    |
| `close`    | `devices,close,<device_id>`                                                                             | Close the physical interface                  |
| `read`     | `devices,read,<device_id>,<n_bytes>`                                                                    | Read n bytes from device, reply as hex string |
| `write`    | `devices,write,<device_id>,<hex_data>`                                                                  | Write hex-encoded bytes to the device         |

> For a single write-then-read round trip to a device, the [`route`](control.md#route-to-downstream-device) command (`route,<device_id>,<hex_payload>[,<read_bytes>]`) opens the interface if needed, writes the payload, and returns the response in one command.

## Provisioning Flow

When `add` is called, the agent:

1. Creates an Atom **entity** with `kind: device` via the entities API
2. Creates an Atom **resource** with `kind: channel` via the resources API
3. **Connects** the gateway to the channel (publish + subscribe)
4. Optionally creates a **save_senml rule** via the Rules Engine API (if `MG_AGENT_RULES_ENGINE_URL` is configured)
5. Saves the device to the local **BoltDB store**

If any step fails, the agent rolls back all previously created resources (gateway, channel) before returning the error.

The device's Atom credentials (entity ID/API key) and channel ID are persisted locally so the agent can reconnect on restart.

## Device Telemetry Scheduler

When a device has a valid channel ID, the agent launches a background goroutine that:

1. Creates a dedicated MQTT connection using the device's credentials (gateway ID as both MQTT gateway ID and username, device secret as password)
2. Opens the physical interface
3. Reads data in a loop (4096-byte buffer)
4. Publishes raw data to `m/<tenant-id>/c/<device-channel-id>/msg`

Reconnection uses exponential backoff (1s to 30s). TLS settings are inherited from the gateway's MQTT configuration.

## Persistence and Migrations

The registry is stored in a BoltDB file (`MG_AGENT_DEVICE_DB_PATH`) so it survives agent restarts. The store tracks an on-disk **schema version** in a `meta` bucket. When the agent opens the database it runs any pending migrations forward to the current schema version inside a single write transaction, so upgrading the agent never loses devices. Databases created by older agent builds (which had no schema version) are treated as version `0` and migrated in place on first open. A database written by a newer agent than the running binary is rejected rather than silently downgraded.

## Backup and Restore

The entire registry can be exported to a portable JSON snapshot and re-imported, either into the same agent or a different one. The snapshot carries the schema version and an export timestamp:

```json
{
  "schema_version": 1,
  "exported_at": "2026-06-23T08:00:00Z",
  "devices": [
    { "id": "...", "name": "...", "interface_type": "serial", "...": "..." }
  ]
}
```

- **Backup** — `GET /devices/backup` returns the snapshot.
- **Restore** — `POST /devices/restore` imports a snapshot. By default devices are **merged** (records with the same ID are overwritten, others are left untouched). Pass `?replace=true` to first clear the existing registry so it matches the snapshot exactly; any open physical interfaces are closed during a replace restore. A snapshot from a newer schema version is rejected, and devices with an empty ID are rejected with `400`. The upload body is capped at 16 MiB.

> A replace restore is an administrative operation and is not synchronized against concurrent interface opens. If a device interface is opened at the same moment a replace restore wipes that device, the interface can be left open with no owning record. Quiesce device activity (or restart the agent) around a replace restore.

```bash
# Back up the registry to a file
curl -s http://localhost:9999/devices/backup | jq . > devices-backup.json

# Restore (merge) on another agent
curl -s -X POST http://localhost:9999/devices/restore \
  -H 'Content-Type: application/json' \
  --data-binary @devices-backup.json

# Restore and replace the existing registry
curl -s -X POST 'http://localhost:9999/devices/restore?replace=true' \
  -H 'Content-Type: application/json' \
  --data-binary @devices-backup.json
```

## Lifecycle Webhooks

When `MG_AGENT_DEVICE_WEBHOOK_URL` is configured, the agent POSTs a JSON event to that URL on device lifecycle changes. Delivery is asynchronous and best-effort: events are queued and sent from a background worker, so webhook latency never blocks device operations. A failed delivery (network error or `5xx`) is retried twice with a short backoff; if the queue overflows (default depth 64) new events are dropped rather than stalling the agent, and each drop is counted and logged at debug level.

| Event                 | Default | Emitted when                             |
| --------------------- | ------- | ---------------------------------------- |
| `device.added`        | yes     | a device is provisioned and registered   |
| `device.removed`      | yes     | a device is deregistered                 |
| `device.iface_opened` | yes     | a device's physical interface is opened  |
| `device.iface_closed` | yes     | a device's physical interface is closed  |
| `device.seen`         | no      | a device is marked seen (live heartbeat) |

`device.seen` is **excluded by default**: the telemetry scheduler marks a device seen on every poll (milliseconds apart), so delivering it would flood the queue and crowd out the lifecycle events. Set `MG_AGENT_DEVICE_WEBHOOK_EVENTS` to an explicit comma-separated allowlist to change which events are delivered (e.g. `device.added,device.removed,device.seen`).

Event payload:

```json
{
  "event": "device.added",
  "device_id": "63bdb473-02e6-457b-bb9a-773a18ab40a7",
  "timestamp": "2026-06-23T08:00:00Z",
  "device": { "id": "63bdb473-...", "name": "temp-sensor", "...": "..." }
}
```

The full `device` record is included on `device.added`; other events carry the `device_id` only.

### Authentication

If `MG_AGENT_DEVICE_WEBHOOK_SECRET` is set, the agent signs the request body with HMAC-SHA256 and sends the signature in the `X-Agent-Webhook-Signature` header as `sha256=<hex>`. The raw secret never travels on the wire, and the receiver can verify both the sender and the payload integrity by recomputing the HMAC over the received body:

```
X-Agent-Webhook-Signature: sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

Use an HTTPS endpoint for the webhook URL; the signature authenticates the payload but does not encrypt it.

## Configuration

### Environment Variables

| Variable                         | Default | Description                                                        |
| -------------------------------- | ------- | ------------------------------------------------------------------ |
| `MG_AGENT_DEVICE_DB_PATH`        |         | Path to the BoltDB database file                                   |
| `MG_AGENT_PROVISION_URL`         |         | Base URL for Atom provisioning API                                 |
| `MG_AGENT_PROVISION_TOKEN`       |         | Token for provisioning API authentication                          |
| `MG_AGENT_RULES_ENGINE_URL`      |         | URL for the Rules Engine (optional, for auto-rules)                |
| `MG_AGENT_DEVICE_WEBHOOK_URL`    |         | Endpoint to receive device lifecycle events (empty disables)       |
| `MG_AGENT_DEVICE_WEBHOOK_SECRET` |         | HMAC-SHA256 key for the `X-Agent-Webhook-Signature` header         |
| `MG_AGENT_DEVICE_WEBHOOK_EVENTS` |         | Comma-separated event allowlist (empty = all except `device.seen`) |

## Topic Map

| Direction     | Topic                             | QoS | Description            |
| ------------- | --------------------------------- | --- | ---------------------- |
| Cloud → Agent | `m/<tenant-id>/c/<ctrl-chan>/req` | 1   | Device command request |
| Agent → Cloud | `m/<tenant-id>/c/<ctrl-chan>/res` | 1   | Command response       |
| Agent → Cloud | `m/<tenant-id>/c/<dev-chan>/msg`  | 0   | Device telemetry data  |

## MQTT Test Recipes

Subscribe to command responses before sending commands:

```bash
mosquitto_sub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> \
    -t "m/<tenant-id>/c/<commands-channel-id>/res" \
    -v
```

### List all devices

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"list"}]'
```

**Response:**

```json
[{ "bn": "req-1", "n": "list", "t": 1781259205.3925076, "vs": "null" }]
```

### Add a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"add,{\"name\":\"temp-sensor\",\"external_id\":\"ext-001\",\"external_key\":\"ext-key-001\",\"iface_type\":\"serial\",\"iface_addr\":\"/dev/ttyS0\"}"}]'
```

**Response:**

```json
[
  {
    "bn": "req-1",
    "n": "add",
    "t": 1781259547.2528343,
    "vs": "{\"id\":\"<device-id>\",\"key\":\"ext-key-001\",\"channel_id\":\"<device-channel-id>\",\"interface_type\":\"serial\",\"interface_addr\":\"/dev/ttyS0\",\"name\":\"temp-sensor\",\"active\":false,\"last_seen\":\"0001-01-01T00:00:00Z\"}"
  }
]
```

### Get a specific device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"get,<device-id>"}]'
```

### Remove a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"remove,<device-id>"}]'
```

### Mark a device as seen

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"seen,<device-id>"}]'
```

### Open a device interface

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"open,<device-id>"}]'
```

### Close a device interface

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"close,<device-id>"}]'
```

### Read bytes from a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"read,<device-id>,64"}]'
```

**Response:**

```json
[{"bn":"req-1:","n":"read","vs":"48656c6c6f20576f726c64","t":...}]
```

### Write bytes to a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"write,<device-id>,48656c6c6f"}]'
```

**Response:**

```json
[{"bn":"req-1:","n":"write","vs":"5","t":...}]
```

### Subscribe to device telemetry

```bash
mosquitto_sub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> \
    -t "m/<tenant-id>/c/<device-channel-id>/msg" \
    -v
```

## Testing with Virtual Serial Ports

When running the agent in a Docker container (Alpine-based), you can use `socat` to create virtual serial port pairs for testing without real hardware.

### Set up virtual serial ports

Inside the agent container:

```bash
apk add socat

# Create a linked virtual serial port pair
socat -d -d pty,raw,echo=0,link=/dev/ttyV0 pty,raw,echo=0,link=/dev/ttyV1 &
```

The agent connects to `/dev/ttyV0` and you interact with `/dev/ttyV1`.

### Add a virtual device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"add,{\"name\":\"dummy-sensor\",\"external_id\":\"ext-dummy\",\"external_key\":\"ext-dummy-key\",\"iface_type\":\"serial\",\"iface_addr\":\"/dev/ttyV0\"}"}]'
```

### Send data to the device (from the container)

```bash
echo "HELLO" > /dev/ttyV1
```

### Open a device interface

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"open,<device-id>"}]'
```

### Read data from the device (via MQTT)

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"read,<device-id>,64"}]'
```

### Write data to the device (via MQTT)

```bash
# "HELLO" in hex = 48454c4c4f
mosquitto_pub \
    -h localhost -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "dev-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"write,<device-id>,48454c4c4f"}]'
```

Verify on the other end:

```bash
cat /dev/ttyV1
```

### Test management flow without hardware

The `list`, `add`, `get`, `remove`, and `seen` subcommands work without physical hardware. You can test these via the HTTP API:

```bash
# List devices
curl -s http://localhost:9999/devices | jq .

# Add a device
curl -s -X POST http://localhost:9999/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "temp-sensor",
    "external_id": "ext-001",
    "external_key": "ext-key-001",
    "interface_type": "serial",
    "interface_address": "/dev/ttyS0"
  }'
```

## HTTP API

| Method   | Path                  | Description                                  |
| -------- | --------------------- | -------------------------------------------- |
| `GET`    | `/devices`            | List all devices                             |
| `GET`    | `/devices/{id}`       | Get a device                                 |
| `POST`   | `/devices`            | Add a device                                 |
| `DELETE` | `/devices/{id}`       | Remove a device                              |
| `POST`   | `/devices/{id}/seen`  | Mark device as seen                          |
| `GET`    | `/devices/backup`     | Export the registry as a JSON snapshot       |
| `POST`   | `/devices/restore`    | Import a snapshot (`?replace=true` to reset) |
| `POST`   | `/devices/{id}/open`  | Open the device's physical interface         |
| `POST`   | `/devices/{id}/close` | Close the device's physical interface        |
| `POST`   | `/devices/{id}/read`  | Read bytes from the device                   |
| `POST`   | `/devices/{id}/write` | Write bytes to the device                    |
