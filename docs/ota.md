# Over-the-Air (OTA) Updates

The OTA subsystem allows remote binary updates of the agent via MQTT. A trigger message causes the agent to download a new binary, verify its integrity, replace the running binary, and restart the process in-place.

## State Machine

The OTA update goes through these states:

| State         | Description                                            |
| ------------- | ------------------------------------------------------ |
| `IDLE`        | No OTA in progress                                     |
| `TRIGGERED`   | Trigger received, download not yet started             |
| `DOWNLOADING` | Binary downloading; progress updates published         |
| `VERIFYING`   | SHA-256 hash verification in progress                  |
| `READY`       | Download and verification complete, about to replace   |
| `RESTARTING`  | Binary replaced, process restarting via `syscall.Exec` |
| `ABORTED`     | OTA cancelled via abort command                        |

## Trigger Payload

OTA can be triggered via two MQTT topics. Both use a multi-record SenML pack.

### Via commands channel (`req`)

**Topic:** `m/<domain-id>/c/<commands-channel-id>/req`

The first record dispatches to the `ota` handler; subsequent records carry the trigger fields:

```json
[
  { "bn": "req-1:", "n": "ota", "vs": "" },
  { "n": "url", "vs": "https://example.com/agent" },
  { "n": "hash", "vs": "<sha256-hex>" },
  { "n": "size", "v": 8388608 }
]
```

### Via OTA config topic

**Topic:** `m/<domain-id>/c/<commands-channel-id>/ota/cfg`

No dispatch record is needed; the entire pack is trigger fields:

```json
[
  { "n": "url", "vs": "https://example.com/agent" },
  { "n": "hash", "vs": "<sha256-hex>" },
  { "n": "size", "v": 8388608 }
]
```

| Field  | Required | Description                                                                                       |
| ------ | -------- | ------------------------------------------------------------------------------------------------- |
| `url`  | Cond.    | HTTP/HTTPS URL to the new binary. Omit on the `ota/cfg` topic to prime MQTT data delivery instead |
| `hash` | No       | Hex-encoded SHA-256 digest. If omitted, the agent tries to fetch `<url>.sha256` as a sidecar file |
| `size` | No       | Expected byte count. If non-zero, the download is aborted if it exceeds this value                |

### Via MQTT data delivery (no HTTP)

For environments without outbound HTTP, firmware can be delivered over MQTT. First **prime** the agent with an `ota/cfg` message carrying `hash` (and optionally `size`) but **no** `url`:

```json
[
  { "n": "hash", "vs": "<sha256-hex>" },
  { "n": "size", "v": 8388608 }
]
```

Then publish the raw binary to the **OTA data topic**:

**Topic:** `m/<domain-id>/c/<commands-channel-id>/ota`

The agent installs the payload only if it matches the primed `size` (when given) and SHA-256 `hash`. A `hash` is **required** for MQTT-delivered firmware (there is no sidecar fallback). The binary is sent as a single MQTT message, so it is bounded by the broker's maximum packet size. A `url`-bearing `ota/cfg` trigger cancels any pending priming.

## Status Reporting

During the OTA operation, the agent publishes a **retained** SenML status message on each state transition and at 5% download increments to:

**Topic:** `m/<domain-id>/c/<commands-channel-id>/ota/status`

```json
[
  { "bn": "gw:", "bt": 1749552000.0, "n": "state", "vs": "downloading" },
  { "n": "bytes", "u": "By", "v": 65536 },
  { "n": "total", "u": "By", "v": 1324740 },
  { "n": "progress", "u": "%", "v": 50.0 }
]
```

| Field      | Unit | Description                                                                  |
| ---------- | ---- | ---------------------------------------------------------------------------- |
| `state`    | —    | `triggered`, `downloading`, `verifying`, `ready`, `restarting`, or `aborted` |
| `bytes`    | `By` | Bytes written to disk so far (meaningful during `downloading`)               |
| `total`    | `By` | Total expected bytes (content length; `0` when unknown)                      |
| `progress` | `%`  | Percentage complete, 0–100                                                   |
| `error`    | —    | Error message; present only on failure (state `aborted`)                     |

Because the message is **retained**, a subscriber that connects mid-update (or after it) reads the last published status immediately. On failure, a final status carrying the `error` field is published.

## Verification

Verification is **mandatory**. The agent will abort the update if:

1. No `hash` field was provided in the trigger **and**
2. The sidecar file at `<url>.sha256` is not reachable

In either case, the downloaded file is deleted and the running binary is left untouched.

If a hash is provided or the sidecar is found, the downloaded file's SHA-256 must match exactly. On mismatch, the download is deleted and the OTA fails.

## Configuration

### Environment Variables

| Variable                    | Default                | Description                                            |
| --------------------------- | ---------------------- | ------------------------------------------------------ |
| `MG_AGENT_OTA_ENABLED`      | `false`                | Enable or disable OTA functionality                    |
| `MG_AGENT_OTA_BINARY_PATH`  | `/usr/local/bin/agent` | Absolute path to the running binary (will be replaced) |
| `MG_AGENT_OTA_DOWNLOAD_DIR` | `/tmp`                 | Directory for the temporary download file              |

## Topic Map

| Direction     | Topic                                    | QoS | Description                                               |
| ------------- | ---------------------------------------- | --- | --------------------------------------------------------- |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/req`        | 1   | Trigger via commands channel (uses `ota` dispatch record) |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/ota/cfg`    | 0   | Direct OTA config trigger / MQTT-delivery priming         |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/ota`        | 0   | Firmware binary for MQTT delivery (after priming)         |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/ota/status` | QoS | Progress and state updates (retained)                     |

## MQTT Test Recipes

### Trigger OTA via commands channel

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"ota","vs":""},{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."},{"n":"size","v":8388608}]'
```

### Trigger OTA via OTA config topic

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/ota/cfg" \
    -m '[{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."}]'
```

### Deliver firmware over MQTT (no HTTP)

Prime with the expected hash and size (no `url`), then publish the raw binary to the OTA data topic:

```bash
HASH=$(sha256sum agent-v2 | cut -d' ' -f1)
SIZE=$(stat -c%s agent-v2)

# 1. Prime the agent
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/ota/cfg" \
    -m "[{\"n\":\"hash\",\"vs\":\"$HASH\"},{\"n\":\"size\",\"v\":$SIZE}]"

# 2. Send the binary
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/ota" \
    -f agent-v2
```

### Abort an in-progress OTA

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"ota","vs":"abort"}]'
```

### Query OTA status via commands channel

Returns the current OTA state (`busy` and `last_error`) as a JSON response on the control response topic:

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"ota","vs":"status"}]'
```

### Trigger OTA with token auth (when command_secret is set)

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/ota/cfg" \
    -m '[{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."},{"n":"token","vs":"my-secret-token"}]'
```

### Subscribe to OTA status updates

```bash
mosquitto_sub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<commands-channel-id>/ota/status" \
    -v
```

**Expected output:**

Download progress is published on every 5% step (`5, 10, 15, … 95, 100`); the lines below are abbreviated with `...`:

```
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"triggered"},{"n":"bytes","u":"By","v":0},{"n":"total","u":"By","v":0},{"n":"progress","u":"%","v":0}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"downloading"},{"n":"bytes","u":"By","v":66237},{"n":"total","u":"By","v":1324740},{"n":"progress","u":"%","v":5}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"downloading"},{"n":"bytes","u":"By","v":132474},{"n":"total","u":"By","v":1324740},{"n":"progress","u":"%","v":10}]
...
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"downloading"},{"n":"bytes","u":"By","v":1258503},{"n":"total","u":"By","v":1324740},{"n":"progress","u":"%","v":95}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"downloading"},{"n":"bytes","u":"By","v":1324740},{"n":"total","u":"By","v":1324740},{"n":"progress","u":"%","v":100}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"verifying"},{"n":"bytes","u":"By","v":0},{"n":"total","u":"By","v":0},{"n":"progress","u":"%","v":100}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"ready"},{"n":"bytes","u":"By","v":0},{"n":"total","u":"By","v":0},{"n":"progress","u":"%","v":100}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"state","vs":"restarting"},{"n":"bytes","u":"By","v":0},{"n":"total","u":"By","v":0},{"n":"progress","u":"%","v":100}]
```

### Check OTA status via HTTP

```bash
curl -s http://localhost:9999/ota/status | jq .
```

**Expected response (idle):**

```json
{
  "busy": false,
  "last_error": ""
}
```

### Trigger OTA via HTTP

```bash
curl -s -X POST http://localhost:9999/ota \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://example.com/agent-v2",
    "sha256": "abcdef1234567890...",
    "size": 8388608
  }'
```
