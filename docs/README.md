# Magistrala Agent Documentation

Per-feature documentation with configuration, MQTT topic maps, and copy-paste test recipes.

| Document                     | Description                                                                                                 |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [heartbeat.md](heartbeat.md) | Self-heartbeat and service liveness tracking, interval configuration, test recipes                          |
| [telemetry.md](telemetry.md) | Periodic uptime telemetry, payload format, runtime configuration, test recipes                              |
| [control.md](control.md)     | Command dispatch registry, agent lifecycle (stop/start/reload/status), runtime config, token auth, exec, route, help |
| [bootstrap.md](bootstrap.md) | Profile-based provisioning flow, environment variables, cache management, test recipes                      |
| [ota.md](ota.md)             | Over-the-air binary updates, trigger payload, download/verify/replace cycle, status reporting, test recipes |
| [terminal.md](terminal.md)   | Interactive terminal sessions over MQTT, session lifecycle, PTY management, test recipes                    |
| [nodered.md](nodered.md)     | Node-RED integration, flow deployment, provisioning, HTTP and MQTT management, test recipes                 |
| [devices.md](devices.md)     | Downstream device provisioning, physical interfaces, device CRUD, telemetry scheduler, test recipes         |
| [health.md](health.md)       | Health supervisor, systemd watchdog integration, MQTT connection monitoring, health check endpoints         |
