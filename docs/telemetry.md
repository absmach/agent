# Telemetry

The telemetry subsystem publishes periodic gateway telemetry data to the Magistrala telemetry channel. In addition to uptime, the agent can collect and report CPU temperature, memory usage, load averages, disk usage, and wireless signal strength from the host. This is distinct from the self-heartbeat (see [heartbeat.md](heartbeat.md)), which includes richer device metadata.

## Overview

When `MG_AGENT_TELEMETRY_INTERVAL` is set to a non-zero duration, the agent starts a background goroutine that publishes a SenML telemetry record at the configured interval. Individual telemetry readers can be enabled or disabled via environment variables or the runtime config. Setting the interval to `0s` disables telemetry entirely.

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
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry" \
    -v
```

**Expected output (repeats every interval):**

```
m/e9692c28-b730-4797-8a15-2e25c08f9641/c/b465a688-c1ca-417d-a36f-71f6f1be2409/gateway/telemetry [{"bn":"gw:","bt":1781188728.6078596,"n":"uptime","u":"s","v":40.125499445},{"n":"heap_free","u":"By","v":4659642368},{"n":"heap_used","u":"By","v":19801149440},{"n":"temperature","u":"Cel","v":99},{"n":"load_avg_1m","v":3.87},{"n":"load_avg_5m","v":3.79},{"n":"load_avg_15m","v":4.24},{"n":"disk_usage_percent","u":"%","v":96.84929070396741},{"n":"devices_active","v":0}]
```

> **Note:** Records for temperature, RSSI, and load average are only present when the corresponding reader is enabled **and** the underlying system file is available. On non-Linux hosts or devices without wireless interfaces, those records are silently omitted.

### Enable telemetry at runtime

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,30s"}]'
```

### Change telemetry interval

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,1m"}]'
```

### Disable telemetry at runtime

Setting the interval to `0s` stops the periodic publishing:

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,telemetry_interval,0s"}]'
```

### Query current telemetry interval

Subscribe to command response:

```bash
mosquitto_sub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> \
    -t "m/<domain-id>/c/<telemetry-channel-id>/res" \
    -v
```

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"get,telemetry_interval"}]'
```

**Response on `m/<domain-id>/c/<ctrl-chan>/res`:**

```json
[{ "bn": "req-1", "n": "get", "t": 1781190613.1251912, "vs": "10s" }]
```

### Reset telemetry interval to startup default

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"reset,telemetry_interval"}]'
```
