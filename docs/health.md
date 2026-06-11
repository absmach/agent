# Health Supervisor and Systemd Watchdog

The health supervisor periodically checks the agent's subsystem health and triggers a process restart if the agent remains unhealthy for too long. When running under systemd, it also sends `WATCHDOG=1` notifications.

## Overview

```
┌─────────────────────────────────┐
│         Health Supervisor        │
│  ┌───────────┐  ┌────────────┐  │
│  │  MQTT     │  │  systemd   │  │
│  │  Checker  │  │  Watchdog  │  │
│  └─────┬─────┘  └─────┬──────┘  │
│        │              │          │
│        ▼              ▼          │
│   ┌─────────────────────────┐   │
│   │  Unhealthy timeout?     │   │
│   │  → syscall.Exec()       │   │
│   └─────────────────────────┘   │
└─────────────────────────────────┘
```

## Health Checkers

| Checker | What it checks         | Failure condition               |
| ------- | ---------------------- | ------------------------------- |
| `mqtt`  | MQTT broker connection | `client.IsConnected() == false` |

Additional checkers can be registered at startup via `supervisor.Register()`.

## Behavior

1. The supervisor runs a periodic ticker at the configured interval
2. Each tick, all registered checkers are polled
3. If any checker reports unhealthy, the unhealthy timer starts
4. If the agent stays unhealthy longer than the timeout, the process is restarted via `syscall.Exec()`
5. If all checkers recover before the timeout, the unhealthy timer resets

## Systemd Watchdog Integration

When the `NOTIFY_SOCKET` environment variable is set (indicating the agent is running under systemd with `WatchdogSec` configured):

- The agent sends periodic `WATCHDOG=1` notifications via the unix datagram socket
- Notifications are only sent when the agent is healthy
- If the agent becomes unhealthy and stops notifying, systemd will kill and restart the process

### Example systemd unit

```ini
[Unit]
Description=Magistrala Agent

[Service]
Type=notify
ExecStart=/usr/local/bin/agent
WatchdogSec=30
Restart=always

[Install]
WantedBy=multi-user.target
```

## Configuration

### Environment Variables

| Variable                     | Default | Description                                     |
| ---------------------------- | ------- | ----------------------------------------------- |
| `MG_AGENT_WATCHDOG_INTERVAL` | `0`     | Health check interval; `0` disables supervision |
| `MG_AGENT_WATCHDOG_TIMEOUT`  | `60s`   | How long unhealthy before triggering restart    |

## HTTP Endpoints

### Health check

```bash
curl -s http://localhost:9999/health | jq .
```

**Response:**

```json
{
  "status": "pass",
  "description": "agent",
  "commit": "abc1234"
}
```

### Prometheus metrics

```bash
curl -s http://localhost:9999/metrics
```

Exposes Prometheus counters and latency histograms for all service methods.

## Troubleshooting

| Symptom                                       | Cause                         | Fix                                        |
| --------------------------------------------- | ----------------------------- | ------------------------------------------ |
| Agent restarts unexpectedly                   | Health check timeout exceeded | Check MQTT broker connectivity             |
| `WATCHDOG=1` not being sent                   | `NOTIFY_SOCKET` not set       | Ensure systemd unit uses `Type=notify`     |
| Agent logs `"health check failed"` repeatedly | MQTT broker disconnected      | Check broker URL, credentials, and network |
