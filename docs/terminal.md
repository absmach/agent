# Terminal Sessions over MQTT

The terminal subsystem provides interactive shell sessions tunneled over MQTT. Each session spawns a bash PTY (pseudo-terminal) on the agent host, and bidirectional I/O is carried in SenML messages. This enables remote terminal access from Magistrala.

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
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "cfg-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,terminal_session_timeout,120s"}]'
```

## Topic Map

| Direction     | Topic                                         | QoS | Description                          |
| ------------- | --------------------------------------------- | --- | ------------------------------------ |
| Cloud → Agent | `m/<tenant-id>/c/<ctrl-chan>/req`             | 1   | Terminal commands (`term` subsystem) |
| Agent → Cloud | `m/<tenant-id>/c/<ctrl-chan>/res/term/<uuid>` | 1   | PTY output for a specific session    |

## MQTT Test Recipes

### Subscribe to terminal output

Open a separate terminal to watch session output:

```bash
mosquitto_sub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> \
    -t "m/<tenant-id>/c/<commands-channel-id>/res/term/#" \
    -v
```

**Expected output:**

```
m/<tenant-id>/c/<commands-channel-id>/res/term/term-1781257973 [{"bn":"term-1781257973","n":"term","t":1781257978.7125685,"vs":"/ # \u001b[6n"}]
```

### Open a terminal session

```bash
UUID="term-$(date +%s)"

# "open" → base64 = b3Blbg==
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "$UUID" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"b3Blbg==\"}]"
```

### Send a command (e.g. `ls`)

```bash
UUID="term-1781257973"

# "char,ls\n" → base64 = Y2hhcixscwo=
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "$UUID" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
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
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "$UUID" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m "[{\"bn\":\"$UUID:\", \"n\":\"term\", \"vs\":\"Y2hhcix1bmFtZSAtYQo=\"}]"
```

### Close a terminal session

```bash
UUID="term-1749552000"

# "close" → base64 = Y2xvc2U=
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "$UUID" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
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

Open `http://localhost:9999`, navigate to the **Terminal** page, and start an interactive shell session. The web-based terminal provides a full-featured VT100/VT220/xterm emulator with proper ANSI escape sequence rendering, native text selection, copy/paste, and browser find. The terminal automatically reconnects if the connection drops.
