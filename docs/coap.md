# CoAP Transport Support

## Overview

The Magistrala IoT Agent now supports CoAP (Constrained Application Protocol) as an alternative transport layer to MQTT. This implementation provides full feature parity with MQTT transport, including DTLS security, observe/notify pattern, and command handling.

## Features

### CoAP

- **Dual Transport Support**: MQTT and CoAP can be used interchangeably via configuration
- **DTLS Security**:
  - Pre-shared key (PSK) authentication
  - X.509 certificate authentication
  - Configurable TLS verification
- **Observe/Notify Pattern**: For command subscriptions and notifications
- **Connection Management**: Keepalive, reconnection, and health monitoring
- **Block-wise Transfer**: Support for large payloads
- **Message Types**: GET, POST, PUT, DELETE operations

### Command Handling

All existing MQTT commands are supported via CoAP:

- `exec` - Execute shell commands
- `config` - View or save runtime config
- `control` - Internal agent control
- `reset` - Reboot device
- `ota` - Trigger or query OTA update
- `ping` - Health check response
- `route` - Forward command to downstream device
- `term` - Terminal session
- `nodered` - Node-RED flow management
- `devices` - Device management commands

### Integration

- **Seamless Integration**: Uses same SenML payload format as MQTT
- **Topic/Path Mapping**: MQTT topics map to CoAP paths
- **Fallback Support**: Can fall back to MQTT on CoAP errors (when configured)
- **Health Monitoring**: Connection status and liveness checks

## Configuration

### Environment Variables

| Variable                        | Description                      | Default          |
| ------------------------------- | -------------------------------- | ---------------- |
| `MG_AGENT_TRANSPORT`            | Transport type: `mqtt` or `coap` | `mqtt`           |
| `MG_AGENT_COAP_URL`             | CoAP server URL (host:port)      | `localhost:5683` |
| `MG_AGENT_COAP_PSK`             | DTLS pre-shared key              | `""`             |
| `MG_AGENT_COAP_CERT_FILE`       | Gateway certificate file path    | `""`             |
| `MG_AGENT_COAP_KEY_FILE`        | Gateway private key file path    | `""`             |
| `MG_AGENT_COAP_CA_FILE`         | CA certificate file path         | `""`             |
| `MG_AGENT_COAP_SKIP_TLS`        | Skip TLS verification            | `true`           |
| `MG_AGENT_COAP_MAX_OBSERVE`     | Max observe registrations        | `8`              |
| `MG_AGENT_COAP_MAX_RETRANSMITS` | Max retransmits                  | `5`              |
| `MG_AGENT_COAP_KEEP_ALIVE`      | Keepalive interval (seconds)     | `0`              |
| `MG_AGENT_COAP_CONTENT_FORMAT`  | Content format (media type)      | `50`             |

### Config File

```toml
[agent]
transport = "coap"  # or "mqtt"

[coap]
url = "coap://coap.magistrala.io:5683"
psk = "shared-secret"
cert_path = "/etc/agent/gateway.crt"
priv_key_path = "/etc/agent/gateway.key"
ca_path = "/etc/agent/ca.crt"
skip_tls_ver = false
max_observe = 8
max_retransmits = 5
keep_alive = 60
content_format = 50
```

## CoAP Path Mapping

MQTT topics are mapped to CoAP paths as follows:

| MQTT Topic                                      | CoAP Path                                        | Method  |
| ----------------------------------------------- | ------------------------------------------------ | ------- |
| `m/{tenant}/c/{ctrl_channel}/req`               | `/m/{tenant}/c/{ctrl_channel}/req`               | OBSERVE |
| `m/{tenant}/c/{ctrl_channel}/res`               | `/m/{tenant}/c/{ctrl_channel}/res`               | POST    |
| `m/{tenant}/c/{data_channel}/gateway/telemetry` | `/m/{tenant}/c/{data_channel}/gateway/telemetry` | POST    |
| `m/{tenant}/c/{data_channel}/gateway/heartbeat` | `/m/{tenant}/c/{data_channel}/gateway/heartbeat` | POST    |
| `m/{tenant}/c/{ctrl_channel}/ota/cfg`           | `/m/{tenant}/c/{ctrl_channel}/ota/cfg`           | OBSERVE |
| `m/{tenant}/c/{ctrl_channel}/ota`               | `/m/{tenant}/c/{ctrl_channel}/ota`               | OBSERVE |
| `m/{tenant}/c/{ctrl_channel}/ota/status`        | `/m/{tenant}/c/{ctrl_channel}/ota/status`        | POST    |

## Usage Examples

### Basic CoAP with DTLS (PSK)

```bash
export MG_AGENT_TRANSPORT=coap
export MG_AGENT_COAP_URL=coap.example.com:5683
export MG_AGENT_COAP_PSK=shared-secret
export MG_AGENT_TENANT_ID=<tenant-id>
export MG_AGENT_CHANNELS_CTRL_ID=<ctrl-channel-id>
export MG_AGENT_CHANNELS_DATA_ID=<data-channel-id>

./build/magistrala-agent
```

### CoAP with DTLS (Certificates)

```bash
export MG_AGENT_TRANSPORT=coap
export MG_AGENT_COAP_URL=coaps://coap.example.com:5684
export MG_AGENT_COAP_CERT_FILE=/etc/agent/gateway.crt
export MG_AGENT_COAP_KEY_FILE=/etc/agent/gateway.key
export MG_AGENT_COAP_CA_FILE=/etc/agent/ca.crt
export MG_AGENT_COAP_SKIP_TLS=false
export MG_AGENT_TENANT_ID=<tenant-id>
export MG_AGENT_CHANNELS_CTRL_ID=<ctrl-channel-id>
export MG_AGENT_CHANNELS_DATA_ID=<data-channel-id>

./build/magistrala-agent
```

### Sending Commands via CoAP

Using the coap-cli tool:

```bash
# Execute command
coap-cli post /m/<tenant>/c/<ctrl-channel>/req \
  --auth <auth-token> \
  -d '[{"bn":"req-1:", "n":"exec", "vs":"ls,-la"}]'

# Ping
coap-cli post /m/<tenant>/c/<ctrl-channel>/req \
  --auth <auth-token> \
  -d '[{"bn":"ping:", "n":"ping", "vs":""}]'

# View config
coap-cli post /m/<tenant>/c/<ctrl-channel>/req \
  --auth <auth-token> \
  -d '[{"bn":"cfg:", "n":"config", "vs":"view"}]'
```

### Observe Gateway Telemetry

```bash
# Observe heartbeat
coap-cli get /m/<tenant>/c/<data-channel>/gateway/heartbeat \
  --auth <auth-token> \
  --observe

# Observe telemetry
coap-cli get /m/<tenant>/c/<data-channel>/gateway/telemetry \
  --auth <auth-token> \
  --observe
```

## DTLS Configuration

### PSK Configuration

Simple DTLS setup using pre-shared keys:

```toml
[coap]
url = "coap://coap.example.com:5683"
psk = "my-secret-psk"
skip_tls_ver = false
```

### Certificate Configuration

More secure DTLS using X.509 certificates:

```toml
[coap]
url = "coaps://coap.example.com:5684"
cert_path = "/etc/agent/gateway.crt"
priv_key_path = "/etc/agent/gateway.key"
ca_path = "/etc/agent/ca.crt"
skip_tls_ver = false
```

### Bootstrap Integration

CoAP credentials can be provisioned via the bootstrap service, similar to MQTT:

```json
{
  "coap": {
    "url": "coaps://coap.magistrala.io:5684",
    "psk": "bootstrap-provisioned-psk",
    "cert_path": "/etc/agent/gateway.crt",
    "priv_key_path": "/etc/agent/gateway.key",
    "ca_path": "/etc/agent/ca.crt"
  }
}
```

## OTA Updates via CoAP

OTA updates are supported over CoAP using the observe pattern:

### OTA Configuration Trigger

```bash
# Observe OTA config resource
coap-cli observe /m/<tenant>/c/<ctrl-channel>/ota/cfg \
  --auth <auth-token> &
# Server will publish OTA config (URL, hash, size)
```

### OTA Data Streaming

```bash
# Observe OTA data resource for firmware streaming
coap-cli observe /m/<tenant>/c/<ctrl-channel>/ota \
  --auth <auth-token> &
# Firmware binary will be streamed in blocks
```

### OTA Status Publishing

```bash
# Observe OTA status for progress updates
coap-cli observe /m/<tenant>/c/<ctrl_channel>/ota/status \
  --auth <auth-token> &
# Status updates will be published periodically
```

## Health Monitoring

The agent monitors CoAP connection health:

- **Connection Status**: Published to health checker
- **Keepalive**: Configurable ping interval
- **Reconnection**: Automatic reconnection on connection loss
- **Graceful Fallback**: Can fall back to MQTT on CoAP failure

## Discovery Service

CoAP supports the `.well-known/core` discovery resource:

```bash
coap-cli get /.well-known/core
```

Returns available resources and their attributes.

## Comparison with MQTT

| Feature             | MQTT              | CoAP                        |
| ------------------- | ----------------- | --------------------------- |
| Transport Layer     | TCP over TLS      | UDP over DTLS               |
| Message Model       | Publish/Subscribe | Request/Response + Observe  |
| Resource Discovery  | No                | Yes (`.well-known/core`)    |
| Group Communication | Yes               | Yes (multicast)             |
| Message Size        | Large             | Small (constrained)         |
| Overhead            | Higher            | Lower                       |
| Latency             | Higher            | Lower                       |
| QoS Levels          | 0, 1, 2           | Confirmable/Non-confirmable |

## References

- [RFC 7252 - The Constrained Application Protocol (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252)
- [RFC 7252 - Observe Option](https://datatracker.ietf.org/doc/html/rfc7641)
- [RFC 7925 - DTLS for CoAP](https://datatracker.ietf.org/doc/html/rfc7925)
- [Aeolus CoAP Implementation](https://github.com/absmach/aeolus)
- [coap-cli Tool](https://github.com/absmach/coap-cli)
