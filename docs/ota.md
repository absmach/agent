# Firmware Updates

Remote firmware update is a durable job controlled over MQTT. Firmware bytes
are downloaded over HTTPS and are not transported through MQTT.

## Start

Call `firmware.update.start`:

```json
{
  "url": "https://artifacts.example.com/agent/agent-linux-arm64",
  "sha256": "64-character-hex-sha256",
  "size": 12345678
}
```

The URL must use HTTPS and the SHA-256 digest is required. The immediate result
is a persisted job:

```json
{
  "id": "job-uuid",
  "type": "firmware.update",
  "state": "queued",
  "progress": 0
}
```

Use:

```text
firmware.update.status.get
firmware.update.abort
job.get
job.list
job.cancel
```

Job state transitions are published at:

```text
m/{domain}/c/{dataChannel}/gateway/jobs/events
```

The update implementation downloads to the configured staging directory,
verifies size and SHA-256, replaces the configured Agent binary and reports
progress. The browser binary-upload tab is intentionally unavailable in remote
mode; upload the artifact to an authorized HTTPS service first.

## Configuration

| Variable | Default |
| --- | --- |
| `MG_AGENT_OTA_ENABLED` | `true` |
| `MG_AGENT_OTA_BINARY_PATH` | `/usr/local/bin/agent` |
| `MG_AGENT_OTA_DOWNLOAD_DIR` | `/tmp` |

Required gateway role:

```text
firmware-admin
```
