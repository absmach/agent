We will keep the existing two-channel Magistrala structure and replace only the remote protocol. The local HTTP UI remains functional.

## Final topic model

### Control channel

Used for requests, responses, desired state and stream input.

| Purpose | Topic |
|---|---|
| Server → Agent RPC | `m/{domain}/c/{control}/req` |
| Agent → Server response | `m/{domain}/c/{control}/res/{requesterId}` |
| Agent → server-service RPC | `m/{domain}/c/{control}/service/{serviceName}/req` |
| Service → Agent response | `m/{domain}/c/{control}/service/{serviceName}/res/{agentId}/{bootId}` |
| Desired state | `m/{domain}/c/{control}/gateway/state/desired` |
| Terminal/log stream control | `m/{domain}/c/{control}/gateway/streams/{sessionId}/control` |
| Terminal input | `m/{domain}/c/{control}/gateway/streams/{sessionId}/in` |

### Data channel

Used for Agent-generated information.

| Purpose | Topic |
|---|---|
| Heartbeat | `m/{domain}/c/{data}/gateway/heartbeat` |
| Telemetry | `m/{domain}/c/{data}/gateway/telemetry` |
| Events | `m/{domain}/c/{data}/gateway/events` |
| Reported state | `m/{domain}/c/{data}/gateway/state/reported` |
| Job progress | `m/{domain}/c/{data}/gateway/jobs/events` |
| Logs/terminal output | `m/{domain}/c/{data}/gateway/streams/{sessionId}/out` |

The existing `/req`, `/res`, `/gateway/heartbeat`, and `/gateway/telemetry` locations are preserved.

API version will be carried in the MQTT `api-version` property and payload schema, not added to the topic.

## Important channel rule

Each Agent must have:

```text
one dedicated control channel
one dedicated data channel
```

Multiple Agents must not share a control channel because every subscribed Agent could execute the same request.

## Phase 1: Define contracts first

Create:

```text
api/openrpc.json
api/asyncapi.yaml
api/schemas/
```

The OpenRPC document will define:

- Every JSON-RPC method.
- Parameter and result schemas.
- Standard application errors.
- Required role or capability.
- Read-only versus mutating methods.
- Idempotency requirements.
- Default expiry.
- Whether the operation returns immediately or starts a job.

The AsyncAPI document will define:

- Control and data topics.
- MQTT 5 properties.
- Request/response correlation.
- QoS and retain rules.
- Telemetry, events and state payloads.
- Stream framing.
- Publisher/subscriber ownership.

## Phase 2: Introduce the JSON-RPC protocol

Replace the existing remote SenML command payload with JSON-RPC 2.0.

Initial methods:

```text
system.health.get
system.snapshot.get

agent.pause
agent.resume
agent.reload

config.get
runtimeConfig.list
runtimeConfig.set

service.list
service.register
service.remove

device.list
device.register
device.remove
device.markSeen

nodeRed.status.get
nodeRed.flows.get
nodeRed.action.execute
```

The RPC dispatcher will call the same Agent service methods already used by the local GoKit HTTP endpoints. Business logic will not be duplicated.

Protocol rules:

- MQTT QoS 1 for RPC.
- No retained RPC requests.
- MQTT Response Topic and Correlation Data.
- JSON-RPC `id` must match MQTT correlation data.
- No batch requests.
- No `null` IDs.
- Explicit request expiry and execution deadline.
- Validate that response topics belong to the correct control channel.

## Phase 3: Reliability and deduplication

Persist the following for mutating requests:

```text
request ID
method
parameter hash
execution state
result or error
expiration
```

Duplicate handling:

- Same request ID and same parameters: return the saved result.
- Same ID with different parameters: reject it.
- Already running: report in-progress.
- Expired request: do not execute it.

Configuration and registry changes will use revisions such as `expectedRevision` to prevent conflicting updates.

## Phase 4: State, events and telemetry

Use three different data behaviours:

| Information | Behaviour |
|---|---|
| CPU, memory, temperature, network, load | Publish periodically as telemetry |
| Heartbeat and presence | Publish periodically |
| Device/service/configuration changes | Publish an event immediately |
| Current configuration/device/service state | Publish retained reported state on startup and change |
| Authoritative current value | Provide through RPC |

Full device and service lists should not be published repeatedly. The Agent publishes them when they change and supports `device.list` and `service.list` for an authoritative refresh.

Desired state is published by the control plane on the control channel. Reported state is published only by the Agent on the data channel.

## Phase 5: Durable jobs

Convert long-running operations into jobs:

```text
firmware.update.start
backup.create
backup.restore
agent.reset
nodeRed.flows.deploy
config.apply
```

Starting an operation returns a `jobId` immediately.

Common job methods:

```text
job.get
job.list
job.cancel
```

Job progress is published on:

```text
m/{domain}/c/{data}/gateway/jobs/events
```

Firmware and large backup files will use HTTPS/object storage. MQTT carries only authorization, metadata, job control and progress.

## Phase 6: Logs and terminal

Do not use JSON-RPC for every log line or terminal character.

RPC creates a bounded session:

```text
log.stream.open
terminal.open
stream.close
```

The result returns:

- Session ID.
- Input and output topics.
- Expiry time.
- Maximum duration.
- Inactivity timeout.
- Byte and rate limits.

Terminal input uses the control channel. Output uses the data channel. Frames include sequence numbers, and nothing is retained.

## Phase 7: Agent Gateway and remote UI

The communication path will be:

```text
Remote browser
   → HTTP/WebSocket
Agent Gateway
   → MQTT control channel
Agent
   → MQTT data/control response
Agent Gateway
   → WebSocket/HTTP response
Remote browser
```

The browser will not receive Magistrala MQTT credentials.

The Agent Gateway will:

- Convert UI operations to OpenRPC requests.
- Track pending requests using correlation IDs.
- Enforce request timeouts.
- Subscribe to responses, telemetry, events, state, jobs and streams.
- Send live changes to the browser over WebSocket.
- Reconstruct the remote UI snapshot after reconnect.

The local UI continues using local HTTP, SSE and WebSocket endpoints directly.

## Phase 8: Security

Use separate identities for the Agent and Agent Gateway.

Agent permissions:

- Subscribe to its control request/input topics.
- Publish its control responses.
- Publish only under its data channel.
- Access only approved server-service RPC topics.

Agent Gateway permissions:

- Publish control requests.
- Subscribe to control responses.
- Subscribe to the corresponding data channel.
- No access to unrelated Agents.

Privileged operations such as terminal, reset, raw device writes and OTA require separate authorization roles and audit records.

## Phase 9: Breaking cutover

There will be no backward-compatible legacy MQTT command protocol.

Cutover order:

1. Complete OpenRPC and AsyncAPI contracts.
2. Implement and test Agent RPC/events/jobs/streams.
3. Update the Agent Gateway and standalone UI.
4. Configure control/data channel ACLs.
5. Stop the old remote control components.
6. Upgrade Agent and Agent Gateway during one maintenance window.
7. Run end-to-end verification.
8. Remove the legacy command decoder and associated tests.

Rollback will use the previous complete container set, not protocol compatibility inside the new version.

## Acceptance criteria

The migration is complete when:

- Every local UI function has an OpenRPC, state, event, job or stream equivalent.
- Control and data channels remain distinct.
- The remote browser contains no MQTT credentials.
- Duplicate mutating requests cannot execute twice.
- Expired commands cannot execute after reconnect.
- Device, service, configuration and OTA changes appear remotely without polling loops.
- Authoritative state can always be retrieved through RPC.
- Terminal and logs have strict session and rate limits.
- Broker ACL tests reject cross-Agent and cross-channel access.
- Local UI and standalone remote UI pass end-to-end Docker tests.
