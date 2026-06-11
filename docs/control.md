# Control — Command Dispatch, Config, and Token Auth

The control subsystem handles inbound MQTT commands from Magistrala, dispatches them to the correct handler, and returns responses on the control response channel. It also provides runtime configuration management (`get`/`set`/`reset`) and optional token-based command authentication.

## Overview

All commands are sent as [SenML][senml] JSON arrays to the **commands channel request topic**. The agent decodes the first record's `n` field to determine the subsystem, then routes to the appropriate handler. Responses are published to the **commands channel response topic**.

### Command Subsystems

| `n` value | Handler       | Description                                                     |
| --------- | ------------- | --------------------------------------------------------------- |
| `exec`    | Execute       | Run an allowlisted shell command                                |
| `config`  | ServiceConfig | View services, get/set/reset runtime config, save export config |
| `service` | ServiceConfig | Alias for `config` — same handler                               |
| `control` | Control       | Node-RED management commands                                    |
| `term`    | Terminal      | Open/close/write interactive terminal sessions                  |
| `nodered` | NodeRed       | Node-RED flow operations                                        |
| `ping`    | Ping          | Publish an immediate heartbeat                                  |
| `reset`   | Reset         | Graceful shutdown and process restart                           |
| `ota`     | OTA           | Over-the-air binary update                                      |
| `devices` | DeviceManager | Downstream device CRUD                                          |

## Architecture

```
┌──────────────┐      MQTT       ┌──────────────────────┐
│  Magistrala  │ ──── req ────── │     Agent Broker     │
│   (cloud)    │                 │  ┌──────────────────┐ │
│              │ ◄─── res ────── │  │  handleMsg()     │ │
└──────────────┘                 │  │    ↓ authorize   │ │
                                 │  │    ↓ dispatch    │ │
                                 │  └──────────────────┘ │
                                 └──────────────────────┘
```

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
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
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
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"view"}]'
```

#### Get a config value

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"get,log_level"}]'
```

**Response:**

```json
[{"bn":"req-1:","n":"get","vs":"info","t":...}]
```

#### Set a config value

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,log_level,debug"}]'
```

**Response:**

```json
[{"bn":"req-1:","n":"set","vs":"ok","t":...}]
```

#### Reset a config value to startup default

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"reset,log_level"}]'
```

#### Invalidate bootstrap cache

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,bs_valid,0"}]'
```

Setting `bs_valid` to `0` deletes the cached bootstrap profile. On next restart, the agent re-fetches from the bootstrap server.

## Execute Commands (exec subsystem)

The `exec` subsystem runs allowlisted shell commands on the agent host.

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
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"pwd"}]'

# With arguments (comma-separated)
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cmd-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'
```

Commands are executed directly (not via a shell), so shell operators like `&&`, `||`, `|`, and `>` are not supported. Each command and its arguments are comma-separated: `ls,-la,/tmp`.

**Response (on control response topic):**

```json
[{"bn":"req-1:","n":"ls -la","vs":"/\ndrwxr-xr-x ...","t":...}]
```

> **Note:** `cd` is handled specially — it changes the agent's internal working directory, so subsequent `exec` commands use the new directory.

## Save Export Config

Push an export service config file to the gateway:

```bash
# Encode the config file
CONTENT=$(base64 -w 0 export.json)

mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"req-1:\", \"n\":\"config\", \"vs\":\"save,export,/path/to/config.toml,$CONTENT\"}]"
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
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "reset-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:","n":"reset","vs":"graceful"}]'
```

With token auth (when `command_secret` is set):

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
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
{
  "service": "agent",
  "response": "reset",
  "mode": "graceful"
}
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

## Troubleshooting

| Symptom                                                   | Cause                                         | Fix                                                    |
| --------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------ |
| Command sent, no response                                 | Token auth enabled but `token` record missing | Add `{"n":"token","vs":"<secret>"}` to your SenML pack |
| Agent logs `"command rejected: invalid or missing token"` | Wrong token value                             | Verify `MG_AGENT_COMMAND_SECRET` matches               |
| Agent logs `"no handler registered for command"`          | Unknown `n` field                             | Check supported subsystems table above                 |
| `exec` returns `"invalid command"`                        | Command not in allowlist                      | Use only allowlisted commands                          |
| `config set` returns `"invalid command"`                  | Invalid key or value format                   | Check settable keys list and value format              |
| `config get` returns `"not_configured"`                   | Persistent config store not initialized       | Check `MG_AGENT_CONFIG_PATH`                           |

[senml]: https://tools.ietf.org/html/rfc8428
