# Terminal Sessions

Terminal access is a privileged bounded stream, not one JSON-RPC request per
keystroke.

## Open

Call:

```text
terminal.open
```

Required role:

```text
terminal-admin
```

The result contains a UUID, expiry, byte limit and exact topics:

```text
m/{domain}/c/{control}/gateway/streams/{sessionId}/control
m/{domain}/c/{control}/gateway/streams/{sessionId}/in
m/{domain}/c/{data}/gateway/streams/{sessionId}/out
```

## Frames

- `control` uses JSON actions such as `resize` and `close`, QoS 1.
- `in` carries raw PTY input, QoS 0.
- `out` carries JSON frames with sequence, timestamp and `dataBase64`, QoS 0.
- No stream message is retained.

Sessions close on absolute expiry, inactivity, byte limit, explicit close,
Agent shutdown or gateway WebSocket disconnection.

The standalone browser connects to:

```text
WS /api/agents/{agentId}/terminal
```

The Agent Gateway opens the MQTT stream and translates browser WebSocket frames.
The browser never receives MQTT credentials or topic permissions.

The embedded local UI continues to use `/terminal/ws` directly.
