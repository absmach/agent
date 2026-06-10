# Terminal Sessions over MQTT

The terminal subsystem provides interactive shell sessions tunneled over MQTT. Each session spawns a bash PTY (pseudo-terminal) on the agent host, and bidirectional I/O is carried in SenML messages. This enables remote terminal access from Magistrala.

## Overview

```
┌──────────────┐    MQTT req     ┌──────────────┐    PTY     ┌──────┐
│  Magistrala  │ ─────────────── │    Agent     │ ────────── │ bash │
│   (cloud)    │                 │  terminal    │            │ PTY  │
│              │ ◄── MQTT res ── │  sessions    │ ◄──────── │      │
└──────────────┘                 └──────────────┘            └──────┘
```

Each terminal session is identified by a UUID (the `bn` prefix). Multiple concurrent sessions are supported.

## Architecture

The agent maintains a map of active terminal sessions. Each session:

1. Spawns a `bash` process attached to a PTY
2. Reads PTY output and publishes it to the agent's response topic under `term/<uuid>`
3. Accepts input bytes via MQTT and writes them to the PTY
4. Has an idle timeout — if no input or output occurs within the timeout, the session closes automatically

## Session Lifecycle

```
  open          char (write)       char (write)       timeout / close
 ──────► ─────────────────► ─────────────────► ─────────────────►
  spawn    write to PTY,       write to PTY,     session removed,
  bash     read PTY output,   read PTY output,  PTY closed
           publish to MQTT    publish to MQTT
```

## Message Format

All terminal commands use the `term` subsystem. The `vs` field is **base64-encoded** and contains a comma-separated payload: `<command>[,<arg>]`.

### Open a session

**Base64 payload:** `open`

**Request:**

```json
[{ "bn": "<uuid>:", "n": "term", "vs": "b3Blbg==" }]
```

(`b3Blbg==` = base64 of `open`)

### Write to a session

**Base64 payload:** `char,<input-bytes>`

**Request:**

```json
[{ "bn": "<uuid>:", "n": "term", "vs": "Y2hhcixscw==" }]
```

(`Y2hhcixscw==` = base64 of `char,ls`)

### Close a session

**Base64 payload:** `close`

**Request:**

```json
[{ "bn": "<uuid>:", "n": "term", "vs": "Y2xvc2U=" }]
```

(`Y2xvc2U=` = base64 of `close`)

### Terminal output (agent → cloud)

Output from the PTY is published as SenML on the control response topic under `term/<uuid>`:

```json
[{ "bn": "<uuid>:", "n": "term", "vs": "<output-text>", "t": ... }]
```

## Configuration

### Environment Variables

| Variable                            | Default | Description                                                                                            |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `MG_AGENT_TERMINAL_SESSION_TIMEOUT` | `60s`   | Idle timeout for terminal sessions. After this duration with no I/O, the session closes automatically. |

### Runtime Config (MQTT set)

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,terminal_session_timeout,120s"}]'
```

## Topic Map

| Direction     | Topic                                         | QoS | Description                          |
| ------------- | --------------------------------------------- | --- | ------------------------------------ |
| Cloud → Agent | `m/<domain-id>/c/<ctrl-chan>/req`             | 1   | Terminal commands (`term` subsystem) |
| Agent → Cloud | `m/<domain-id>/c/<ctrl-chan>/res/term/<uuid>` | 1   | PTY output for a specific session    |

## MQTT Test Recipes

### Open a terminal session

```bash
UUID="term-$(date +%s)"

# "open" → base64 = b3Blbg==
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "$UUID" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"b3Blbg==\"}]"
```

### Subscribe to terminal output

Open a separate terminal to watch session output:

```bash
mosquitto_sub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> \
  -t "m/<domain-id>/c/<commands-channel-id>/res/term/#" \
  -v
```

**Expected output:**

```
m/<domain-id>/c/<ctrl-chan>/res/term/term-1749552000 [{"bn":"term-1749552000:","n":"term","vs":"bash-5.2$ ","t":...}]
```

### Send a command (e.g. `ls`)

```bash
UUID="term-1749552000"

# "char,ls\n" → base64 = Y2hhcixscwo=
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "$UUID" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"Y2hhcixscwo=\"}]"
```

The subscriber terminal will show the `ls` output followed by a new shell prompt.

### Send multiple commands in sequence

```bash
UUID="term-1749552000"

# "char,uname -a\n"
echo -n "char,uname -a" | base64
# Y2hhcix1bmFtZSAtYQ==

mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "$UUID" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"Y2hhcix1bmFtZSAtYQo=\"}]"
```

### Close a terminal session

```bash
UUID="term-1749552000"

# "close" → base64 = Y2xvc2U=
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "$UUID" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"Y2xvc2U=\"}]"
```

### Helper: base64-encode terminal commands

```bash
# Encode a shell command for the terminal subsystem
echo -n "char,ls -la" | base64
# Y2hhcixscyAtbGE=

# Encode with newline (to actually execute the command)
printf "char,ls -la\n" | base64
# Y2hhcixscyAtbGEK
```

### Use the Agent UI terminal

Open `http://localhost:3002`, navigate to the **Execute Command** panel, and type shell commands. The UI handles base64 encoding and session management automatically.

## Troubleshooting

| Symptom                                          | Cause                                         | Fix                                                                                   |
| ------------------------------------------------ | --------------------------------------------- | ------------------------------------------------------------------------------------- |
| `open` succeeds but no output appears            | PTY read error or publish failure             | Check agent logs for `"Error sending data"`                                           |
| Session closes immediately after opening         | Idle timeout too short                        | Increase `MG_AGENT_TERMINAL_SESSION_TIMEOUT`                                          |
| `"no such terminal session"` on close            | Session already timed out or was never opened | Open a new session first                                                              |
| Command sent but no output                       | Missing newline (`\n`) in the char payload    | Use `printf "char,<cmd>\n" \| base64` to include the newline                          |
| Agent logs `"failed to create terminal session"` | PTY or bash not available                     | Ensure `bash` is installed and `/dev/pts` is mounted (in Docker: `--device /dev/pts`) |
| Multiple sessions conflict                       | Same UUID used for different sessions         | Use a unique UUID per session                                                         |
