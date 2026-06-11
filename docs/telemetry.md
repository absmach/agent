# Telemetry

The telemetry subsystem publishes periodic gateway telemetry data to the Magistrala telemetry channel. In addition to uptime, the agent can collect and report CPU temperature, memory usage, load averages, disk usage, and wireless signal strength from the host. This is distinct from the self-heartbeat (see [heartbeat.md](heartbeat.md)), which includes richer device metadata.

## Overview

When `MG_AGENT_TELEMETRY_INTERVAL` is set to a non-zero duration, the agent starts a background goroutine that publishes a SenML telemetry record at the configured interval. Individual telemetry readers can be enabled or disabled via environment variables or the runtime config. Setting the interval to `0s` disables telemetry entirely.

## Architecture

```
┌──────────────────────────────────┐   MQTT publish    ┌──────────────┐
│             Agent                │ ───────────────── │  Magistrala  │
│  ┌────────────────────────────┐  │   every N seconds │   MQTT broker│
│  │     Gateway Telemetry      │  │                   └──────┬───────┘
│  │  ┌──────┐ ┌──────┐        │  │                          │
│  │  │ Uptime│ │Memory│        │  │                     Rule Engine
│  │  └──────┘ └──────┘        │  │                     save_senml
│  │  ┌──────┐ ┌──────┐        │  │                          │
│  │  │  CPU  │ │ Disk │        │  │                    ┌─────▼──────┐
│  │  │ Temp  │ │Usage │        │  │                    │ Timeseries │
│  │  └──────┘ └──────┘        │  │                    │     DB     │
│  │  ┌──────┐ ┌──────┐        │  │                    └────────────┘
│  │  │Load   │ │Wire- │        │  │
│  │  │Avg    │ │less  │        │  │
│  │  └──────┘ └──────┘        │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

## Telemetry Readers

The following telemetry readers are available. All readers are Linux-specific and are silently skipped when the underlying data source is unavailable.

| Reader              | Record Name                                  | Unit  | Source                                   | Default   |
| ------------------- | -------------------------------------------- | ----- | ---------------------------------------- | --------- |
| **Uptime**          | `uptime`                                     | `s`   | Go runtime `time.Since(startTime)`       | Always on |
| **Memory**          | `heap_free`, `heap_used`                     | `By`  | `/proc/meminfo` (MemTotal, MemAvailable) | Always on |
| **Disk**            | `disk_usage_percent`                         | `%`   | `syscall.Statfs("/")`                    | Always on |
| **CPU Temperature** | `temperature`                                | `Cel` | `/sys/class/thermal/thermal_zone*/temp`  | On        |
| **Network RSSI**    | `rssi`                                       | `dB`  | `/proc/net/wireless` (default interface) | On        |
| **Load Average**    | `load_avg_1m`, `load_avg_5m`, `load_avg_15m` | —     | `/proc/loadavg`                          | On        |

Uptime, memory, and disk usage are always included. CPU temperature, network RSSI, and load average can be toggled via environment variables or the runtime config.

## Payload Format

**Topic:** `m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry`

**Payload (all readers enabled):**

```json
[
  { "bn": "gw:", "bt": 1749552000.0, "n": "uptime", "u": "s", "v": 3600.5 },
  { "n": "heap_free", "u": "By", "v": 524288.0 },
  { "n": "heap_used", "u": "By", "v": 1048576.0 },
  { "n": "temperature", "u": "Cel", "v": 52.3 },
  { "n": "rssi", "u": "dB", "v": -65.0 },
  { "n": "load_avg_1m", "v": 0.75 },
  { "n": "load_avg_5m", "v": 0.82 },
  { "n": "load_avg_15m", "v": 0.68 },
  { "n": "disk_usage_percent", "u": "%", "v": 45.2 }
]
```

| Field | Type   | Description                                        |
| ----- | ------ | -------------------------------------------------- |
| `bn`  | string | Base name: always `"gw:"`                          |
| `bt`  | float  | Unix timestamp (seconds with nanosecond precision) |
| `n`   | string | Measurement name (see readers table above)         |
| `u`   | string | Unit (SenML standard units)                        |
| `v`   | float  | Measured value                                     |

## Configuration

### Environment Variables

| Variable                                 | Default | Description                                                                                                   |
| ---------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------- |
| `MG_AGENT_TELEMETRY_INTERVAL`            | `30s`   | Telemetry publish interval. Set to a positive duration (e.g. `30s`, `1m`) to enable. `0s` disables telemetry. |
| `MG_AGENT_TELEMETRY_INCLUDE_TEMPERATURE` | `true`  | Include CPU temperature reading from thermal zones                                                            |
| `MG_AGENT_TELEMETRY_INCLUDE_NETWORK`     | `true`  | Include wireless RSSI reading from `/proc/net/wireless`                                                       |
| `MG_AGENT_TELEMETRY_INCLUDE_LOAD`        | `true`  | Include 1/5/15-minute load averages from `/proc/loadavg`                                                      |

### Runtime Config (MQTT set)

Telemetry can be enabled or reconfigured at runtime:

```
config set telemetry_interval <duration>
```

Setting to a positive value starts the ticker if it was not running, or resets the interval. Setting to `0s` or an invalid value stops the telemetry goroutine.

Allowed range: `1s` – `1h`.

## Topic Map

| Direction     | Topic                                           | QoS          | Description        |
| ------------- | ----------------------------------------------- | ------------ | ------------------ |
| Agent → Cloud | `m/<domain-id>/c/<data-chan>/gateway/telemetry` | Configurable | Periodic telemetry |

## MQTT Test Recipes

### Subscribe to telemetry

```bash
mosquitto_sub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry" \
  -v
```

**Expected output (repeats every interval):**

```
m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry [{"bn":"gw:","bt":1749552000.0,"n":"uptime","u":"s","v":42.5},{"n":"heap_free","u":"By","v":...},{"n":"heap_used","u":"By","v":...},{"n":"temperature","u":"Cel","v":52.3},{"n":"rssi","u":"dB","v":-65},{"n":"load_avg_1m","v":0.75},{"n":"load_avg_5m","v":0.82},{"n":"load_avg_15m","v":0.68},{"n":"disk_usage_percent","u":"%","v":45.2}]
```

> **Note:** Records for temperature, RSSI, and load average are only present when the corresponding reader is enabled **and** the underlying system file is available. On non-Linux hosts or devices without wireless interfaces, those records are silently omitted.

### Enable telemetry at runtime

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,30s"}]'
```

### Change telemetry interval

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,1m"}]'
```

### Disable telemetry at runtime

Setting the interval to `0s` stops the periodic publishing:

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,0s"}]'
```

### Query current telemetry interval

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"get,telemetry_interval"}]'
```

**Response on `m/<domain-id>/c/<ctrl-chan>/res`:**

```json
[{"bn":"req-1:","n":"get","vs":"30s","t":...}]
```

### Reset telemetry interval to startup default

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"reset,telemetry_interval"}]'
```

## Troubleshooting

| Symptom                                        | Cause                                        | Fix                                                                          |
| ---------------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------- |
| No telemetry messages                          | Interval is `0s` (disabled)                  | Set `MG_AGENT_TELEMETRY_INTERVAL` or use `config set telemetry_interval 30s` |
| Telemetry stops after config change            | Interval set to `0s` or invalid value        | Use a valid Go duration between `1s` and `1h`                                |
| Agent logs `"failed to encode self-telemetry"` | Internal SenML encoding error                | Check agent version and report a bug                                         |
| Telemetry messages not stored                  | Rule Engine `save_senml` rule not configured | Ensure the provisioning script created the rule binding                      |
| Missing temperature reading                    | Thermal zone file not found                  | Check `/sys/class/thermal/thermal_zone*/temp` exists on the host             |
| Missing RSSI reading                           | No wireless interface or not using wireless  | Check `/proc/net/wireless` exists and the default interface is wireless      |
| Missing load average                           | `/proc/loadavg` not available                | Only available on Linux hosts                                                |
