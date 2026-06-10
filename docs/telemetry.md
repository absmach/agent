# Telemetry

The telemetry subsystem publishes periodic agent uptime data to the Magistrala telemetry channel. This is distinct from the self-heartbeat (see [heartbeat.md](heartbeat.md)), which includes richer device metadata.

## Overview

When `MG_AGENT_TELEMETRY_INTERVAL` is set to a non-zero duration, the agent starts a background goroutine that publishes a minimal SenML uptime record at the configured interval. Setting the interval to `0s` (the default) disables telemetry.

## Architecture

```
┌──────────────┐   MQTT publish    ┌──────────────┐
│    Agent     │ ───────────────── │  Magistrala  │
│  telemetry   │   every N seconds │   MQTT broker│
│  goroutine   │                   └──────┬───────┘
└──────────────┘                          │
                                    Rule Engine
                                    save_senml
                                          │
                                    ┌──────▼───────┐
                                    │  Timeseries  │
                                    │    DB        │
                                    └──────────────┘
```

## Payload Format

**Topic:** `m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry`

**Payload:**

```json
[
  {
    "bn": "gw:",
    "bt": 1749552000.0,
    "n": "uptime",
    "u": "s",
    "v": 3600.5
  }
]
```

| Field | Type   | Description                                        |
| ----- | ------ | -------------------------------------------------- |
| `bn`  | string | Base name: always `"gw:"`                          |
| `bt`  | float  | Unix timestamp (seconds with nanosecond precision) |
| `n`   | string | Measurement name: always `"uptime"`                |
| `u`   | string | Unit: always `"s"` (seconds)                       |
| `v`   | float  | Uptime in seconds since agent process started      |

## Configuration

### Environment Variables

| Variable                      | Default | Description                                                                                                   |
| ----------------------------- | ------- | ------------------------------------------------------------------------------------------------------------- |
| `MG_AGENT_TELEMETRY_INTERVAL` | `0s`    | Telemetry publish interval. Set to a positive duration (e.g. `30s`, `1m`) to enable. `0s` disables telemetry. |

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
m/<domain-id>/c/<telemetry-channel-id>/gateway/telemetry [{"bn":"gw:","bt":1749552000.0,"n":"uptime","u":"s","v":42.5}]
```

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

Currently, setting the interval to `0s` stops the periodic publishing:

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
| No telemetry messages                          | Interval is `0s` (disabled by default)       | Set `MG_AGENT_TELEMETRY_INTERVAL` or use `config set telemetry_interval 30s` |
| Telemetry stops after config change            | Interval set to `0s` or invalid value        | Use a valid Go duration between `1s` and `1h`                                |
| Agent logs `"failed to encode self-telemetry"` | Internal SenML encoding error                | Check agent version and report a bug                                         |
| Telemetry messages not stored                  | Rule Engine `save_senml` rule not configured | Ensure the provisioning script created the rule binding                      |
