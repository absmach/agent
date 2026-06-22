# Device Manager — Downstream Device Provisioning and Management

The device manager subsystem allows the agent to provision, register, and manage downstream devices connected via physical interfaces (serial, I2C, Modbus RTU/TCP, USB). Each device is provisioned as a Magistrala client with its own channel, and data from the device is forwarded to Magistrala over MQTT.

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

1. Creates a Magistrala **Client** via the Clients API
2. Creates a Magistrala **Channel** via the Channels API
3. **Connects** the client to the channel (publish + subscribe)
4. Optionally creates a **save_senml rule** via the Rules Engine API (if `MG_AGENT_RULES_ENGINE_URL` is configured)
5. Saves the device to the local **BoltDB store**

If any step fails, the agent rolls back all previously created resources (client, channel) before returning the error.

The device's Magistrala credentials (client ID/key) and channel ID are persisted locally so the agent can reconnect on restart.

## Device Telemetry Scheduler

When a device has a valid channel ID, the agent launches a background goroutine that:

1. Creates a dedicated MQTT connection using the device's credentials (client ID as both MQTT client ID and username, device secret as password)
2. Opens the physical interface
3. Reads data in a loop (4096-byte buffer)
4. Publishes raw data to `m/<domain-id>/c/<device-channel-id>/msg`

Reconnection uses exponential backoff (1s to 30s). TLS settings are inherited from the gateway's MQTT configuration.

## Configuration

### Environment Variables

| Variable                    | Default | Description                                         |
| --------------------------- | ------- | --------------------------------------------------- |
| `MG_AGENT_DEVICE_DB_PATH`   |         | Path to the BoltDB database file                    |
| `MG_AGENT_PROVISION_URL`    |         | Base URL for Magistrala provisioning API            |
| `MG_AGENT_PROVISION_TOKEN`  |         | Token for provisioning API authentication           |
| `MG_AGENT_RULES_ENGINE_URL` |         | URL for the Rules Engine (optional, for auto-rules) |

## Topic Map

| Direction     | Topic                             | QoS | Description            |
| ------------- | --------------------------------- | --- | ---------------------- |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/req` | 1   | Device command request |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/res` | 1   | Command response       |
| Agent → Cloud | `m/<domain-id>/c/<dev-chan>/msg`  | 0   | Device telemetry data  |

## MQTT Test Recipes

Subscribe to command responses before sending commands:

```bash
mosquitto_sub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<commands-channel-id>/res" \
    -v
```

### List all devices

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"add,{\"name\":\"temp-sensor\",\"external_id\":\"ext-001\",\"external_key\":\"ext-key-001\",\"iface_type\":\"serial\",\"iface_addr\":\"/dev/ttyS0\"}"}]'
```

**Response:**

```json
[
  {
    "bn": "req-1",
    "n": "add",
    "t": 1781259547.2528343,
    "vs": "{\"id\":\"63bdb473-02e6-457b-bb9a-773a18ab40a7\",\"key\":\"ext-key-001\",\"channel_id\":\"e90c8f2d-8063-4762-971a-f3628460423f\",\"interface_type\":\"serial\",\"interface_addr\":\"/dev/ttyS0\",\"name\":\"temp-sensor\",\"active\":false,\"last_seen\":\"0001-01-01T00:00:00Z\"}"
  }
]
```

### Get a specific device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"get,<device-id>"}]'
```

### Remove a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"remove,<device-id>"}]'
```

### Mark a device as seen

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"seen,<device-id>"}]'
```

### Open a device interface

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"open,<device-id>"}]'
```

### Close a device interface

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"close,<device-id>"}]'
```

### Read bytes from a device

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<device-channel-id>/msg" \
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
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"open,<device-id>"}]'
```

### Read data from the device (via MQTT)

```bash
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"devices","vs":"read,<device-id>,64"}]'
```

### Write data to the device (via MQTT)

```bash
# "HELLO" in hex = 48454c4c4f
mosquitto_pub \
    -h localhost -p 1883 \
    -u <client-id> -P <client-secret> --id "dev-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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

| Method   | Path                 | Description         |
| -------- | -------------------- | ------------------- |
| `GET`    | `/devices`           | List all devices    |
| `GET`    | `/devices/{id}`      | Get a device        |
| `POST`   | `/devices`           | Add a device        |
| `DELETE` | `/devices/{id}`      | Remove a device     |
| `POST`   | `/devices/{id}/seen` | Mark device as seen |
