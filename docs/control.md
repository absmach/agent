# Control — Command Dispatch, Config, and Token Auth

The control subsystem handles inbound MQTT commands from Magistrala, dispatches them to the correct handler, and returns responses on the control response channel. It also provides runtime configuration management (`get`/`set`/`reset`) and optional token-based command authentication.

## Overview

All commands are sent as [SenML][senml] JSON arrays to the **commands channel request topic**. The agent decodes the first record's `n` field to determine the subsystem, then routes to the appropriate handler. Responses are published to the **commands channel response topic**.

### Command Subsystems

The dispatch registry is extensible — handlers can be registered at runtime — and each command carries metadata (description, usage) surfaced by the `help` command.

| `n` value | Handler       | Description                                                     |
| --------- | ------------- | --------------------------------------------------------------- |
| `exec`    | Execute       | Run an allowlisted shell command                                |
| `config`  | ServiceConfig | View services, get/set/reset runtime config, save export config |
| `service` | ServiceConfig | Alias for `config` — same handler                               |
| `control` | Control       | Agent lifecycle (stop/start/reload/status) and Node-RED passthrough |
| `term`    | Terminal      | Open/close/write interactive terminal sessions                  |
| `nodered` | NodeRed       | Node-RED flow operations                                        |
| `ping`    | Ping          | Publish an immediate heartbeat                                  |
| `reset`   | Reset         | Graceful shutdown and process restart                           |
| `ota`     | OTA           | Over-the-air binary update (trigger/status/abort)              |
| `devices` | DeviceManager | Downstream device CRUD                                          |
| `route`   | Route         | Forward a payload to a downstream device interface              |
| `help`    | —             | List available commands and their usage                         |

Authorization is enforced **per command**: when a command secret is configured, each command that requires auth must carry a matching `token` record in the SenML pack (see [Token Authentication](#token-authentication)).

## Message Format

### Request (cloud → agent)

**Topic:** `m/<domain-id>/c/<commands-channel-id>/req`

```json
[{ "bn": "<uuid>:", "n": "<subsystem>", "vs": "<command>[,<args>]" }]
```

| Field | Description                                                       |
| ----- | ----------------------------------------------------------------- |
| `bn`  | Request UUID followed by `:` (used to correlate request/response) |
| `n`   | Subsystem name (see table above)                                  |
| `vs`  | Comma-delimited command and arguments                             |

### Response (agent → cloud)

**Topic:** `m/<domain-id>/c/<commands-channel-id>/res`

```json
[
  {
    "bn": "<uuid>:",
    "n": "<command>",
    "vs": "<response-body>",
    "t": 1749552000.0
  }
]
```

## Token Authentication

When `MG_AGENT_COMMAND_SECRET` is set to a non-empty string, **all inbound MQTT commands** (except service heartbeats) must include a `token` record in the SenML pack. The agent uses constant-time comparison to prevent timing attacks.

### Enable token auth

```bash
export MG_AGENT_COMMAND_SECRET="my-secret-token"
```

### Send an authenticated command

```json
[
  { "bn": "req-1:", "n": "exec", "vs": "pwd" },
  { "n": "token", "vs": "my-secret-token" }
]
```

When the secret is configured and the token is missing or does not match, the agent logs:

```
Command rejected: invalid or missing token
```

and silently drops the message (no response is published).

### Set the command secret at runtime

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,command_secret,my-secret-token"}]'
```

> **Note:** The `get` command returns `REDACTED` for `command_secret` to avoid leaking the secret over MQTT.

## Runtime Configuration (config subsystem)

The `config` command provides runtime management of agent parameters without restart.

### Settable Keys

| Key                        | Format                                     | Description                         |
| -------------------------- | ------------------------------------------ | ----------------------------------- |
| `log_level`                | `debug`, `info`, `warn`, `error`           | Log verbosity                       |
| `heartbeat_interval`       | Go duration (e.g. `30s`, `1m`)             | Self-heartbeat period; minimum `1s` |
| `telemetry_interval`       | Go duration (`1s`–`1h`) or `0s` to disable | Telemetry publish period            |
| `terminal_session_timeout` | Go duration (e.g. `60s`, `5m`)             | Terminal session idle timeout       |
| `command_secret`           | Any non-empty string                       | Token for MQTT command auth         |
| `bs_valid`                 | `0` or `1`                                 | Bootstrap cache validity flag       |
| `mqtt_password`            | Any non-empty string                       | MQTT broker password (write-only)   |
| `provision_token`          | Any non-empty string                       | Provisioning API token (write-only) |

> **Note:** `mqtt_password` and `provision_token` are credential keys. They can be `set` but `get` returns `"not_allowed"` to avoid leaking secrets over MQTT.

### Commands

#### View registered services

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"view"}]'
```

Response will be something like this:

Channel `m/<domain-id>/c/<commands-channel-id>/res`

```json
[
  {
    "bn": "req-1",
    "n": "view",
    "t": 1781191691.7735436,
    "vs": "[{\"name\":\"nodered\",\"last_seen\":\"2026-06-11T15:28:08.943017256Z\",\"status\":\"online\",\"type\":\"nodered\",\"terminal\":0}]"
  }
]
```

#### Get a config value

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"get,log_level"}]'
```

**Response:**

```json
[{ "bn": "req-1", "n": "get", "t": 1781192457.305233, "vs": "debug" }]
```

#### Set a config value

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,log_level,debug"}]'
```

**Response:**

```json
[{ "bn": "req-1", "n": "set", "t": 1781192515.7082806, "vs": "ok" }]
```

#### Reset a config value to startup default

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"reset,log_level"}]'
```

#### Invalidate bootstrap cache

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,bs_valid,0"}]'
```

Setting `bs_valid` to `0` deletes the cached bootstrap profile. On next restart, the agent re-fetches from the bootstrap server.

## Execute Commands (exec subsystem)

The `exec` subsystem runs allowlisted shell commands on the agent host via MQTT. **This subsystem is no longer accessible through the web UI** - use the new **Terminal** page for interactive shell access.

### Allowlisted Commands

```
cat  cd  curl  date  df  echo  env  false  free  hostname  id
ifconfig  ip  journalctl  ls  netstat  ping  printf  ps  pwd
ss  systemctl  true  uname  uptime  who
```

### Execute a command

```bash
# No arguments
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"exec", "vs":"pwd"}]'

# With arguments (comma-separated)
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'
```

Commands are executed directly (not via a shell), so shell operators like `&&`, `||`, `|`, and `>` are not supported. Each command and its arguments are comma-separated: `ls,-la,/tmp`.

**Response (on control response topic):**

```json
[{ "bn": "req-1", "bt": 1781192628.4707563, "n": "pwd", "vs": "/\n" }]
```

```json
[
  {
    "bn": "req-1",
    "bt": 1781192641.2791781,
    "n": "ls -la",
    "vs": "total 22096\ndrwxr-xr-x    1 root     root             6 Jun 11 15:39 .\ndrwxr-xr-x    1 root     root             6 Jun 11 15:39 ..\n-rwxr-xr-x    1 root     root      22622370 Jun 11 15:39 exe\ndrwxr-xr-x    1 root     root             0 Jun 11 15:39 bin\ndrwxr-xr-x    5 root     root           340 Jun 11 15:39 dev\ndrwxr-xr-x    1 root     root             56 Jun 11 15:39 etc\n-rwxr-xr-x    1 root     root      22622370 Jun 11 15:39 exe\ndrwxr-xr-x    1 root     root             0 Jun 11 15:39 home\ndrwxr-xr-x    1 root     root             146 Jun 11 15:39 lib\ndrwxr-xr-x    1 root     root            28 Jun 11 15:39 media\ndrwxr-xr-x    1 root     root             0 Jun 11 15:39 mnt\ndrwxr-xr-x    1 root     root             0 Jun 11 15:39 opt\ndr-xr-xr-x    1073 root     root             0 Jun 11 15:39 proc\ndrwx------    1 root     root             0 Jun 11 15:39 root\ndrwxr-xr-x    1 root     root             8 Jun 11 15:39 run\ndrwxr-xr-x    1 root     root           810 Jun 11 15:39 sbin\ndrwxr-xr-x    1 root     root             0 Jun 11 15:39 srv\ndr-xr-xr-x   13 root     root             0 Jun 11 15:39 sys\ndrwxrwxrwt    1 root     root             0 Jun 11 15:39 tmp\ndrwxr-xr-x    1 root     root            40 Jun 11 15:39 usr\ndrwxr-xr-x    1 root     root             6 Dec 17 07:03 var\n"
  }
]
```

> **Note:** `cd` is handled specially — it changes the agent's internal working directory, so subsequent `exec` commands use the new directory.

## Save Export Config

Push an export service config file to the gateway:

```bash
# Encode the config file
CONTENT=$(base64 -w 0 export.json)

mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"req-1:\", \"n\":\"config\", \"vs\":\"save,export,/path/to/config.toml,$CONTENT\"}]"
```

## Agent Lifecycle (control subsystem)

The `control` command manages the running agent without restarting the process. `reset` (below) is used for a full process restart.

| `vs`         | Behavior                                                                              | Response                              |
| ------------ | ------------------------------------------------------------------------------------- | ------------------------------------- |
| `stop`       | Pause the heartbeat, telemetry, and device-scheduler loops; the process stays alive   | `stopped`                             |
| `start`      | Resume the paused loops and restart the device scheduler                              | `started`                             |
| `reload`     | Re-apply persisted runtime config overrides (validated; invalid values are skipped)   | `reloaded` or `reloaded:<keys>`       |
| `status`     | Report current runtime state                                                          | `{running, paused, uptime_seconds, version}` JSON |
| `nodered-*`  | Node-RED passthrough (see [nodered.md](nodered.md))                                   | command-specific                      |

```bash
# Pause background publishing (agent stays alive), then resume
mosquitto_pub ... -m '[{"bn":"req-1:","n":"control","vs":"stop"}]'
mosquitto_pub ... -m '[{"bn":"req-1:","n":"control","vs":"start"}]'

# Re-apply persisted overrides and report status
mosquitto_pub ... -m '[{"bn":"req-1:","n":"control","vs":"reload"}]'
mosquitto_pub ... -m '[{"bn":"req-1:","n":"control","vs":"status"}]'
```

## Route to Downstream Device

The `route` command forwards a hex payload to a registered device's physical interface (opening it if needed), then optionally reads back `<read_bytes>` and returns them as a hex string. With no `read_bytes`, the number of bytes written is returned.

```bash
# Write bytes 01 a2 ff to <device-id> and read 16 bytes back
mosquitto_pub ... -m '[{"bn":"req-1:","n":"route","vs":"<device-id>,01a2ff,16"}]'
```

A missing device returns a clear "device not found" error. See [devices.md](devices.md) for device provisioning.

## Discover Commands (help)

The `help` command returns the registry as a JSON array of `{name, description, usage}`:

```bash
mosquitto_pub ... -m '[{"bn":"req-1:","n":"help","vs":""}]'
```

## Reset (process restart)

The `reset` command performs a graceful shutdown and then replaces the running process in-place via `syscall.Exec()`. The agent supports multiple reset modes:

| Mode        | Behavior                                                                                  |
| ----------- | ----------------------------------------------------------------------------------------- |
| `graceful`  | Send goodbye heartbeat, stop service tickers, close terminals, disconnect MQTT, then exec |
| `immediate` | Minimal cleanup, quick MQTT disconnect (100ms), then exec                                 |
| `now`       | Alias for `immediate`                                                                     |
| `watchdog`  | Save reset reason and delegate to the health supervisor (no exec)                         |

If no mode is specified, `graceful` is used by default.

> **Warning:** `graceful`, `immediate`, and `now` modes restart the agent process immediately. Use with caution in production.

### Via MQTT

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "reset-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"reset","vs":"graceful"}]'
```

With token auth (when `command_secret` is set):

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "reset-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:","n":"reset","vs":"immediate"},{"n":"token","vs":"my-secret-token"}]'
```

### Via HTTP

```bash
curl -s -X POST http://localhost:9999/reset \
  -H 'Content-Type: application/json' \
  -d '{"mode":"graceful"}'
```

**Response (HTTP 202 Accepted):**

```json
{ "service": "agent", "response": "reset", "mode": "graceful" }
```

### Goodbye Heartbeat

On a graceful reset, the agent publishes a goodbye heartbeat before disconnecting:

```json
[
  { "bn": "agent:", "n": "service_type", "vs": "agent" },
  { "n": "heartbeat", "vb": false }
]
```

This allows downstream consumers to detect the agent going offline without waiting for a timeout.

### Reset Reason

The reset reason (`graceful`, `immediate`, `watchdog`) is persisted in the config store key `reset_reason` before the process exits. On the next start, the agent (or external tooling) can read this value to determine why the previous instance exited.

## Topic Map

| Direction     | Topic                             | QoS | Description      |
| ------------- | --------------------------------- | --- | ---------------- |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/req` | 1   | Command request  |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/res` | 1   | Command response |

[senml]: https://tools.ietf.org/html/rfc8428
