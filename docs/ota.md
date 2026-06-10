# Over-the-Air (OTA) Updates

The OTA subsystem allows remote binary updates of the agent via MQTT. A trigger message causes the agent to download a new binary, verify its integrity, replace the running binary, and restart the process in-place.

## Overview

```
┌──────────────┐  MQTT trigger   ┌──────────────┐  HTTP GET    ┌──────────────┐
│  Magistrala  │ ──────────────► │    Agent     │ ──────────── │  File Server │
│   (cloud)    │                 │   OTA Run    │ ◄─────────── │  (binary +   │
│              │ ◄── progress ── │              │   download   │   .sha256)   │
└──────────────┘                 └──────┬───────┘              └──────────────┘
                                        │
                                   verify + replace
                                        │
                                   syscall.Exec()
                                   (process replaced)
```

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
| `url`  | Yes      | HTTP/HTTPS URL to the new binary                                                                  |
| `hash` | No       | Hex-encoded SHA-256 digest. If omitted, the agent tries to fetch `<url>.sha256` as a sidecar file |
| `size` | No       | Expected byte count. If non-zero, the download is aborted if it exceeds this value                |

## Status Reporting

During the OTA operation, the agent publishes progress to:

**Topic:** `m/<domain-id>/c/<commands-channel-id>/ota/status`

```json
[
  { "bn": "gw:", "bt": 1749552000.0, "n": "ota_state", "vs": "downloading" },
  { "n": "ota_progress", "u": "%", "v": 50.0 }
]
```

Progress is reported at 5% increments during download and at state transitions.

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
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/ota/cfg`    | 0   | Direct OTA config trigger                                 |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/ota/status` | QoS | Progress and state updates                                |

## MQTT Test Recipes

### Trigger OTA via commands channel

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:","n":"ota","vs":""},{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."},{"n":"size","v":8388608}]'
```

### Trigger OTA via OTA config topic

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/ota/cfg" \
  -m '[{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."}]'
```

### Trigger OTA with token auth (when command_secret is set)

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "ota-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/ota/cfg" \
  -m '[{"n":"url","vs":"https://example.com/agent-v2"},{"n":"hash","vs":"abcdef1234567890..."},{"n":"token","vs":"my-secret-token"}]'
```

### Subscribe to OTA status updates

```bash
mosquitto_sub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<commands-channel-id>/ota/status" \
  -v
```

**Expected output:**

```
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"triggered"},{"n":"ota_progress","u":"%","v":0}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"downloading"},{"n":"ota_progress","u":"%","v":5}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"downloading"},{"n":"ota_progress","u":"%","v":50}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"verifying"},{"n":"ota_progress","u":"%","v":100}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"ready"},{"n":"ota_progress","u":"%","v":100}]
m/<domain-id>/c/<ctrl-chan>/ota/status [{"bn":"gw:","bt":...,"n":"ota_state","vs":"restarting"},{"n":"ota_progress","u":"%","v":100}]
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

## Troubleshooting

| Symptom                                                           | Cause                                                     | Fix                                                       |
| ----------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Agent logs `"OTA is disabled"`                                    | `MG_AGENT_OTA_ENABLED=false`                              | Set `MG_AGENT_OTA_ENABLED=true`                           |
| Agent logs `"OTA already in progress"`                            | A previous OTA is still running                           | Wait for it to finish or check `/ota/status`              |
| Agent logs `"ota verify: no hash provided and sidecar not found"` | Neither `hash` field nor sidecar `<url>.sha256` available | Provide the `hash` field or host a `.sha256` sidecar file |
| Agent logs `"sha256 mismatch"`                                    | Downloaded binary doesn't match expected hash             | Verify the binary on the file server hasn't changed       |
| Agent logs `"server returned HTTP 404"`                           | Binary URL is wrong                                       | Check the `url` field                                     |
| Agent logs `"download exceeded expected size"`                    | `size` field set too low or binary is corrupt             | Verify the actual binary size                             |
| Agent logs `"ota download: ... context canceled"`                 | Agent was shut down during download                       | Re-trigger the OTA after restart                          |
| Binary replaced but agent doesn't come back                       | New binary crashes on startup                             | Check the binary is valid for the target architecture     |
