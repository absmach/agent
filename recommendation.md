# Recommendation

For your gateway, the best fit is a **standards-based RPC profile**, rather than one large device-management framework:

| Layer                        | Recommended standard                               |
| ---------------------------- | -------------------------------------------------- |
| Transport                    | **MQTT 5.0**                                       |
| Request/response routing     | MQTT 5 **Response Topic** and **Correlation Data** |
| RPC message format           | **JSON-RPC 2.0**                                   |
| Method and schema contract   | **OpenRPC**                                        |
| MQTT topic/API documentation | **AsyncAPI 3.1**                                   |
| Persistent configuration     | Desired/reported state documents                   |
| Long-running operations      | Durable job state machine                          |
| Logs and terminal            | Separate bounded stream protocol                   |
| Security                     | Per-gateway mTLS identity and broker ACLs          |

This combination is the strongest match for your actual requirement:

* Server can call the gateway.
* Gateway can call server-side services.
* Either side can be requester or responder.
* You can migrate your existing HTTP, WebSocket, and SSE local APIs incrementally.
* You are not forced into someone else’s device data model.
* OTA, configuration, telemetry, logs, terminal, and bootstrap can use appropriate patterns rather than forcing everything through synchronous RPC.

MQTT 5 standardizes Response Topic and Correlation Data properties intended for request/reply, including copying the correlation data into the response. However, MQTT does not define method names, parameters, results, application errors, authorization, or job semantics; its request/response discussion is guidance around the transport properties, not a complete RPC protocol. ([OASIS Open][1])

JSON-RPC 2.0 supplies the missing application envelope: `method`, `params`, `id`, `result`, and structured `error`. It is transport-independent, so it can be carried cleanly inside MQTT messages. A JSON-RPC notification intentionally receives no response, which is why notifications should not be used for important control commands. JSON-RPC 2.0 is a published specification, not an IETF RFC. ([JSON-RPC][2])

OpenRPC describes your JSON-RPC methods and their parameter/result schemas, while AsyncAPI describes the MQTT channels, bindings, messages, security, and dynamic reply addresses. ([spec][3])

---

# The important architectural conclusion

After reviewing the major standards, I did not find one widely adopted standard that simultaneously gives you all of the following without imposing a substantial external architecture:

1. Arbitrary RPC initiated in both directions.
2. Bootstrap and certificate lifecycle.
3. Persistent desired configuration.
4. Telemetry and event distribution.
5. Durable OTA and maintenance jobs.
6. Interactive logs and terminal streams.
7. A custom gateway data model.

The correct solution is to use **four communication patterns over the same MQTT connection**:

| Plane            | Used for                                               |
| ---------------- | ------------------------------------------------------ |
| RPC              | Short request/result operations                        |
| Jobs             | OTA, restore, reset, deployment, backup                |
| State and events | Configuration reconciliation, telemetry, notifications |
| Streams          | Logs, terminal, sustained device data                  |

Trying to represent all four as RPC will create timeout, retry, duplicate-execution, offline-device, and scaling problems.

---

# Comparison with the main alternatives

| Candidate                     |          Arbitrary calls in both directions | Bootstrap and lifecycle | Fit for your gateway                          | Verdict                               |
| ----------------------------- | ------------------------------------------: | ----------------------: | --------------------------------------------- | ------------------------------------- |
| **MQTT 5 + JSON-RPC 2.0**     |                                   Excellent | Must be profiled by you | Custom Linux/edge gateway with many functions | **Recommended**                       |
| **BBF USP / TR-369**          |                 Possible, but role-oriented |               Excellent | Broadband gateways, CPE, TR-181 ecosystems    | Best full management alternative      |
| **OMA LwM2M 1.2.2**           |     Limited to its client/server operations |               Excellent | Constrained IoT endpoints                     | Not the best fit                      |
| **Sparkplug 3.0**             |            Command metrics, not general RPC |                 Limited | Industrial telemetry/state                    | Useful supplement, insufficient alone |
| **W3C WoT Thing Description** | Describes actions, not the complete runtime |                 Limited | Semantic discovery                            | Optional descriptive layer            |
| **oneM2M**                    |               Has request/response bindings |               Extensive | Large service-layer ecosystems                | Probably too heavy                    |
| **WAMP**                      |                        Excellent routed RPC |                Not MQTT | Systems able to replace MQTT                  | Not applicable here                   |

## BBF USP / TR-369

USP is the strongest standardized **complete remote-management framework** for a broadband or CPE gateway. The current specification is Issue 1 Amendment 5, published in January 2026. It includes MQTT transport, subscriptions, object models, operations, access control, onboarding, asynchronous operations, firmware management, and Protobuf encoding. ([usp.technology][4])

Its normal role model, however, is directional: Controllers send messages to Agents, and Agents send messages or notifications to Controllers. A USP Service may contain both an Agent and a Controller, so fully arbitrary reverse calls are possible by deploying dual roles at both ends, but that adds complexity. ([usp.technology][4])

Choose USP instead of the lighter profile when:

* Your gateway is broadband/CPE equipment.
* TR-181 data-model interoperability is important.
* Third-party controllers must manage your gateway.
* You prefer an extensive prescribed management framework over a custom API.

For a custom gateway containing Node-RED, physical-device interfaces, backup/restore, terminal, and custom services, USP is viable but likely heavier than necessary.

## OMA LwM2M

LwM2M provides bootstrap, registration, Read, Write, Execute, Observe/Notify, Send, and standardized firmware-update objects. This is very good for constrained IoT devices. Execute is normally Server-to-Client, while Send and notifications move data Client-to-Server; it is not an arbitrary symmetric service-RPC system. ([openmobilealliance.org][5])

Its MQTT binding intentionally avoids dependence on MQTT 5 features and defines its own CBOR operations, tokens, and topic structure. Consequently, adopting LwM2M would mean adopting the LwM2M object and operation model rather than simply improving your current API. ([openmobilealliance.org][6])

## Sparkplug

Sparkplug gives excellent industrial MQTT conventions for birth/death certificates, state, typed metrics, and device/node commands. Its standard command path uses NCMD/DCMD metric writes, while custom command meaning remains implementation-defined. It does not provide a general method/params/result/error RPC contract comparable to JSON-RPC. ([Eclipse Sparkplug][7])

## W3C Web of Things

A WoT Thing Description can describe gateway properties, actions, events, schemas, and protocol bindings. This can be useful for semantic discovery, but it does not itself solve durable jobs, bootstrap, authorization, retries, or device lifecycle. ([W3C][8])

---

# Proposed bidirectional MQTT topic model

Use separate request destinations for gateways and logical server services.

```text
m/{tenant}/c/{controlChannel}/req
m/{tenant}/c/{controlChannel}/res/{serverInstanceId}

m/{tenant}/c/{controlChannel}/service/{serviceName}/req
m/{tenant}/c/{controlChannel}/service/{serviceName}/res/{agentId}/{bootId}
```

## Server calls gateway

Server instance `control-42` calls gateway `G17`:

```text
PUBLISH topic:
m/acme/c/CTRL17/req

MQTT Response Topic:
m/acme/c/CTRL17/res/control-42
```

The gateway subscribes to:

```text
m/acme/c/CTRL17/req
```

The server subscribes to:

```text
m/acme/c/+/res/control-42
```

## Gateway calls server

Gateway `G17`, current boot `B9`, calls the provisioning service:

```text
PUBLISH topic:
m/acme/c/CTRL17/service/provisioning/req

MQTT Response Topic:
m/acme/c/CTRL17/service/provisioning/res/G17/B9
```

The gateway subscribes to:

```text
m/acme/c/CTRL17/service/provisioning/res/G17/B9
```

Provisioning service instances can use an MQTT shared subscription:

```text
$share/provisioning-workers/m/acme/c/+/service/provisioning/req
```

That lets one available server instance process the request while the gateway remains unaware of server topology. MQTT 5’s request/response guidance explicitly permits shared subscriptions for responders. ([OASIS Open][1])

## Why this layout is preferable

The responder publishes responses under the target’s namespace:

* Gateway publishes responses under its own gateway namespace.
* Server service publishes responses under its own service namespace.
* Callers receive only their designated response slice.

This makes broker ACLs easier and reduces the permissions needed by each participant.

Do not create one common response topic for the entire fleet. It creates cross-device data exposure, contention, and denial-of-service risks. The USP MQTT specification similarly cautions about designs that concentrate replies into one reply topic. ([usp.technology][4])

---

# MQTT properties for every RPC request

| MQTT property            | Recommended value                    |
| ------------------------ | ------------------------------------ |
| QoS                      | `1`                                  |
| Retain                   | `false`                              |
| Response Topic           | Deterministic reply topic            |
| Correlation Data         | Raw 16-byte request UUID             |
| Message Expiry Interval  | Maximum useful lifetime of request   |
| Content Type             | `application/json`                   |
| Payload Format Indicator | `1`, meaning UTF-8                   |
| User Property            | `api-version=1`                      |
| User Property            | Optional tracing and operation class |

JSON sent over networks should be UTF-8, and `application/json` is its registered media type. ([RFC Editor][9])

The response must:

* Publish to the supplied, validated Response Topic.
* Copy the Correlation Data unchanged.
* Use QoS 1 and `retain=false`.
* Contain the same JSON-RPC `id`.
* Have a bounded Message Expiry Interval.

Subscribe to the response topic before publishing the request, as recommended by the MQTT 5 request/response flow. ([OASIS Open][1])

---

# JSON-RPC payload

## Request

```json
{
  "jsonrpc": "2.0",
  "id": "019b1a8c-384f-7cc0-8fd8-60bc142fd850",
  "method": "device.interface.write",
  "params": {
    "deviceId": "rs485-1",
    "dataBase64": "AQIDBA==",
    "expectedRevision": 17
  }
}
```

## Successful response

```json
{
  "jsonrpc": "2.0",
  "id": "019b1a8c-384f-7cc0-8fd8-60bc142fd850",
  "result": {
    "bytesWritten": 4,
    "revision": 18
  }
}
```

## Error response

```json
{
  "jsonrpc": "2.0",
  "id": "019b1a8c-384f-7cc0-8fd8-60bc142fd850",
  "error": {
    "code": -32010,
    "message": "Device is busy",
    "data": {
      "reason": "DEVICE_BUSY",
      "retryable": true,
      "retryAfterMs": 5000
    }
  }
}
```

Use the same UUID in:

* MQTT Correlation Data, encoded as 16 binary bytes.
* JSON-RPC `id`, encoded as a canonical UUID string.

Reject a response where those identifiers disagree.

Use UUIDv7 once the gateway has reliable time because it is time ordered and contains a Unix-epoch millisecond timestamp. Before the gateway clock has been established during bootstrap, UUIDv4 is safer. ([RFC Editor][10])

## JSON-RPC profile decisions

For the first version:

* Do not permit `null` IDs.
* Do not permit batch requests.
* Do not use notifications for control operations.
* Reserve notifications only for explicitly fire-and-forget information.
* Keep transport metadata in MQTT properties.
* Keep Magistrala's `m/{tenant}/c/{channel}` topic hierarchy and put the major API version in the MQTT `api-version` User Property.
* Use additive changes only within `v1`.
* Do not create custom method names beginning with `rpc.` because that namespace is reserved by JSON-RPC.
* Publish an OpenRPC document for all methods, parameters, results, errors, and authorization classes.
* Optionally implement OpenRPC’s `rpc.discover` mechanism for development and diagnostic environments. ([spec][3])

---

# Reliability and duplicate execution

This is one of the most important parts of the design.

MQTT QoS 1 provides **at-least-once delivery**, so duplicate messages are possible. ([OASIS Open][1])

Therefore every mutating method must be idempotent or deduplicated.

## Required deduplication behavior

For each request, persist:

```text
request ID
method
hash of parameters
state: received | running | completed
response or error
expiry time
```

When a duplicate arrives:

* Same ID, method, and parameter hash: replay the stored response.
* Same ID but different method or parameters: reject as an ID-conflict/security error.
* Existing request still running: return an in-progress result or wait according to the method profile.
* Expired deduplication record: treat according to a documented retention policy.

Do not assume MQTT QoS 2 gives exactly-once business execution. It controls MQTT protocol delivery, but application crashes can occur after an operation executes and before the application records or publishes its response. Idempotency is still required.

## Use optimistic concurrency

Configuration and registry changes should include a revision:

```json
{
  "expectedRevision": 17
}
```

Return a conflict if the active revision is no longer 17.

This prevents two remote operators or automatic controllers from silently overwriting each other.

## Expiration

Set MQTT Message Expiry Interval so the broker removes obsolete queued commands. MQTT defines this property as the message lifetime in seconds and removes messages that can no longer be delivered within that lifetime. ([OASIS Open][1])

Also enforce an application deadline. Message expiry protects the broker queue, but it does not prevent an application from executing a request that was already delivered and then delayed internally.

Suggested values:

| Operation              |                                    Expiry |
| ---------------------- | ----------------------------------------: |
| Health/config read     |                             15–30 seconds |
| Normal control request |                            30–120 seconds |
| Physical I/O operation |                              5–30 seconds |
| Reboot/reset approval  |                             15–30 seconds |
| Terminal control       |                              5–10 seconds |
| Job submission         | 5–30 minutes, depending on offline policy |

Never allow an old retained or queued reboot, terminal-open, factory-reset, or raw-write command to execute after an unexpected reconnection.

## Persistent MQTT sessions

A nonzero Session Expiry Interval allows MQTT session state and subscriptions to survive temporary disconnects. That is useful for intermittently connected gateways. ([OASIS Open][1])

Nevertheless:

* Persistent configuration intent should use desired state.
* Long-running work should use jobs.
* Online-only commands should have short expiry.
* Terminal operations should never wait indefinitely offline.

A MQTT PUBACK is not an application success response. It means the MQTT delivery step was acknowledged, not that the requested action succeeded.

---

# Map of your current local UI to the remote design

I reviewed the supplied CSV. It contains 47 local operations spanning HTTP, WebSocket, SSE, OTA upload, physical-device access, Node-RED, backup/restore, logs, and an interactive terminal.

## 1. Short RPC methods

Use RPC for operations normally completed within a few seconds:

| Current UI area        | Suggested methods                                                    |
| ---------------------- | -------------------------------------------------------------------- |
| Health/status          | `system.health.get`, `system.snapshot.get`                           |
| Configuration reads    | `config.get`, `runtimeConfig.list`                                   |
| Lifecycle controls     | `agent.pause`, `agent.resume`, `agent.reload`                        |
| Services               | `service.list`, `service.register`, `service.remove`                 |
| Devices                | `device.list`, `device.register`, `device.remove`, `device.markSeen` |
| Physical interface     | `device.interface.open`, `.close`, `.read`, `.write`                 |
| Runtime setting        | `runtimeConfig.set`                                                  |
| Node-RED reads/actions | `nodeRed.status.get`, `nodeRed.flows.get`, `nodeRed.action.execute`  |
| OTA status             | `firmware.update.status.get`                                         |

Reads may be retried safely. Mutations require request deduplication and, where relevant, `expectedRevision`.

## 2. Durable jobs

These should not keep one RPC request open until completion:

* Firmware update.
* Device-registry restore.
* Full gateway reset.
* Backup creation.
* Node-RED deployment.
* Full configuration replacement when it causes service restarts.
* Large downstream-device operations.

Example start request:

```json
{
  "jsonrpc": "2.0",
  "id": "019b1a8c-8844-73bd-a67d-c24f48c93ee3",
  "method": "firmware.update.start",
  "params": {
    "artifactId": "agent-4.8.0-linux-arm64",
    "expectedCurrentVersion": "4.7.2"
  }
}
```

Immediate response, returned only after the job has been durably recorded:

```json
{
  "jsonrpc": "2.0",
  "id": "019b1a8c-8844-73bd-a67d-c24f48c93ee3",
  "result": {
    "jobId": "019b1a8c-a179-7cc4-af91-5b108b35014e",
    "state": "queued"
  }
}
```

Job states:

```text
queued
running
waiting
succeeded
failed
cancelled
```

Job API:

```text
job.get
job.cancel
job.list
```

Job event topic:

```text
m/{tenant}/c/{dataChannel}/gateway/jobs/events
```

Example event:

```json
{
  "schemaVersion": 1,
  "jobId": "019b1a8c-a179-7cc4-af91-5b108b35014e",
  "type": "firmware.update",
  "state": "running",
  "progress": {
    "phase": "download",
    "percent": 62
  },
  "sequence": 7
}
```

## 3. Desired and reported state

Do not use expiring RPC as the only way to manage configuration. RPC means “do this now.” Desired state means “make this true when possible.”

```text
m/{tenant}/c/{controlChannel}/gateway/state/desired
m/{tenant}/c/{dataChannel}/gateway/state/reported
```

Both can be retained, with strict publisher ownership:

* Only the control plane publishes `desired`.
* Only the gateway publishes `reported`.

Desired example:

```json
{
  "schemaVersion": 1,
  "generation": 42,
  "config": {
    "telemetryIntervalSeconds": 30,
    "logLevel": "info",
    "nodeRedEnabled": true
  }
}
```

Reported example:

```json
{
  "schemaVersion": 1,
  "revision": 108,
  "appliedDesiredGeneration": 42,
  "bootId": "019b1a86-5eab-7752-adc9-692ad25a2518",
  "agentVersion": "4.8.0",
  "configHash": "sha256:24e7...",
  "status": "ready"
}
```

The gateway should report:

* Which desired generation it applied.
* Whether application succeeded.
* Any validation or runtime error.
* Its active configuration hash and revision.

This is analogous to the separation made by cloud device twins/shadows and by standardized device-management systems: current state and desired state have different reliability semantics.

## 4. Telemetry and events

Telemetry is not RPC:

```text
m/{tenant}/c/{dataChannel}/gateway/telemetry
```

For frequent measurements such as CPU, memory, signal, temperature, load, and disk usage:

* QoS 0 for high-frequency, replaceable measurements.
* QoS 1 for important, lower-frequency measurements.
* `retain=false`.
* Include a sequence number and `bootId`.
* Batch related measurements into one message where practical.

Events:

```text
m/{tenant}/c/{dataChannel}/gateway/events
```

Use QoS 1 for events such as:

* Configuration applied or rejected.
* Device registered or removed.
* Service state changed.
* OTA phase changed.
* Security or authorization failure.
* Unexpected process restart.
* Downstream device connected or disconnected.

Your current `/ws` change notifications naturally migrate to this event topic.

## 5. Logs

Replace the current SSE log feed with a bounded subscription/session:

```text
m/{tenant}/c/{controlChannel}/gateway/streams/{sessionId}/control
m/{tenant}/c/{dataChannel}/gateway/streams/{sessionId}/out
```

A server first calls:

```text
log.stream.open
```

The gateway returns a `sessionId`, expiration, and limits.

Log frames should contain:

```json
{
  "sessionId": "019b1a91-...",
  "sequence": 178,
  "timestamp": "2026-07-23T12:15:31.478Z",
  "stream": "stderr",
  "line": "connection to downstream device timed out"
}
```

Use QoS 0 for ordinary live logs and QoS 1 only for explicitly important audit/security records. Persist important logs elsewhere rather than relying on MQTT stream delivery.

## 6. Interactive terminal

Do not send one JSON-RPC request per keystroke.

Use a separately authorized session:

```text
m/{tenant}/c/{controlChannel}/gateway/streams/{sessionId}/control
m/{tenant}/c/{controlChannel}/gateway/streams/{sessionId}/in
m/{tenant}/c/{dataChannel}/gateway/streams/{sessionId}/out
```

Recommended behavior:

* `terminal.open` is an RPC request.
* Result contains session topics, expiration, window size, and maximum bytes.
* Control messages use QoS 1.
* Keyboard/output data usually uses QoS 0.
* Frames carry sequence numbers.
* Session has an absolute lifetime and inactivity timeout.
* No retained messages.
* Close stream immediately on gateway reboot, authorization expiry, or server disconnect policy.
* Terminal is disabled by default and enabled only by just-in-time authorization.

MQTT can carry a terminal stream, but it should be treated as a privileged support channel, not as an ordinary gateway API.

---

# OTA and file handling

Use MQTT to control the OTA job, not normally to transport the full firmware image.

Recommended flow:

1. Server creates or selects an approved firmware artifact.
2. Server starts a firmware job through RPC.
3. Gateway obtains a signed, short-lived HTTPS URL.
4. Gateway downloads with resume support.
5. Gateway verifies size, digest, signature, hardware compatibility, and anti-rollback version.
6. Gateway installs into an inactive/A-B slot.
7. Gateway restarts and performs a health check.
8. Gateway confirms the new version or automatically rolls back.
9. Job publishes its final state.

Both USP and LwM2M define firmware flows that support downloading from a URI rather than requiring the management messaging transport to carry the complete binary. ([usp.technology][4])

The manifest should include at least:

```text
artifact ID
product and hardware model
firmware version
minimum bootloader version
size
SHA-256 digest
signing key ID
digital signature
anti-rollback counter
installation policy
health-check timeout
```

RFC 9019 provides an IoT firmware-update architecture, and RFC 9124 defines a SUIT manifest information model that is worth using as a reference for interoperable firmware metadata. ([RFC Editor][11])

Your existing “upload firmware binary” UI can become:

1. Browser uploads firmware to the server’s artifact store.
2. Server validates and signs/approves it.
3. Server sends an OTA job to the gateway.
4. Gateway downloads through HTTPS.

Use MQTT chunk transfer only as a fallback for environments where HTTPS artifact retrieval is impossible. A chunk protocol needs chunk IDs, digest verification, retransmission, flow control, and storage quotas.

Apply the same pattern to backup and restore files.

---

# Bootstrap and identity

A safe bootstrap sequence is:

```text
Factory identity
      ↓
Bootstrap connection
      ↓
Enrollment and ownership validation
      ↓
Unique operational certificate
      ↓
Operational MQTT broker and ACL profile
      ↓
Initial desired configuration
      ↓
Reported ready state
```

## Recommended bootstrap identity

Each gateway should have one unique factory credential:

* Prefer a hardware-protected private key.
* Never use one shared fleet password.
* Identify product, serial number, and manufacturing authority.
* Restrict factory credentials to the bootstrap environment.

For formal zero-touch onboarding, BRSKI uses manufacturer-installed X.509 credentials and a manufacturer authorization service to establish ownership and a domain identity. EST defines certificate enrollment and re-enrollment over an authenticated TLS/HTTPS channel. ([RFC Editor][12])

A practical implementation can use:

* BRSKI when manufacturer-assisted ownership vouchers and multivendor automation are required.
* EST for operational certificate enrollment and renewal.
* A product-specific claim-code enrollment flow when the complete BRSKI architecture is unnecessary.

## Bootstrap RPC examples initiated by gateway

```text
bootstrap.enroll
credential.certificate.renew
configuration.initial.get
artifact.downloadAuthorization.get
time.source.get
service.endpoint.resolve
```

After enrollment:

* Issue a unique operational mTLS certificate.
* Install the operational broker address.
* Install tenant and gateway identity.
* Install allowed topic patterns.
* Retire or strongly restrict the factory credential.
* Publish initial reported capabilities.
* Receive the initial desired-state generation.

---

# Security requirements

## TLS

Use MQTT over TLS with mutual authentication.

Current TLS deployment guidance says not to use TLS 1.0 or TLS 1.1, to support TLS 1.2, and to support and prefer TLS 1.3 where possible. ([RFC Editor][13])

## Broker ACLs

Gateway `G17` should be allowed to:

```text
SUB m/acme/c/CTRL17/req
PUB m/acme/c/CTRL17/res/+
PUB m/acme/c/DATA17/gateway/state/reported
PUB m/acme/c/DATA17/gateway/telemetry
PUB m/acme/c/DATA17/gateway/events
PUB m/acme/c/DATA17/gateway/jobs/events

PUB m/acme/c/CTRL17/service/{approved-service}/req
SUB m/acme/c/CTRL17/service/{approved-service}/res/G17/+
```

It should not be allowed to publish another gateway’s state or subscribe to another gateway’s response topics.

## Important MQTT identity limitation

The broker authenticates the publisher, but standard MQTT does not automatically forward the original publisher’s authenticated identity to subscribers.

Therefore:

* The broker must enforce who may publish each request topic.
* The gateway must not trust an unsigned `"actor"` field in the JSON.
* Human authorization should normally happen in the server control service.
* For highly privileged commands, use a short-lived signed capability token bound to:

  * gateway ID,
  * method,
  * request ID,
  * operator or service identity,
  * expiry,
  * permitted parameters or scope.

Separate request topics by coarse privilege class when useful:

```text
.../rpc/ops/req
.../rpc/admin/req
.../rpc/support/req
```

Do not create a separate topic for every method; that becomes operationally difficult. Keep the method in the JSON-RPC payload and use topics only for routing and coarse authorization.

## Privileged operations

The following require stronger authorization and audit:

* Terminal session.
* Firmware downgrade.
* Full configuration replacement.
* Device-registry restore.
* Factory reset.
* Raw physical-interface write.
* Node-RED flow deployment.
* Credential rotation.

For every mutating operation record:

```text
verified service/operator identity
gateway ID
request ID
method
parameters hash
received time
execution start/end
result or error
old/new revision
job ID, if applicable
```

## Limits

Enforce:

* Maximum MQTT payload size.
* Maximum JSON nesting and string sizes.
* Per-gateway request rate.
* Maximum concurrent requests.
* Maximum concurrent jobs.
* Maximum terminal/log stream duration.
* Method allowlists by gateway capability.
* Strict JSON Schema validation before execution.

---

# Presence is not health

Use MQTT Last Will for connectivity presence:

```text
m/{tenant}/c/{dataChannel}/gateway/presence
```

The gateway configures a retained Will such as:

```json
{
  "online": false,
  "reason": "connection-lost"
}
```

After the gateway has initialized—not merely after TCP connection—it publishes:

```json
{
  "online": true,
  "bootId": "019b1a86-5eab-7752-adc9-692ad25a2518",
  "agentVersion": "4.8.0",
  "state": "ready"
}
```

Presence means that the MQTT connection appears active. It does not prove that the agent, Node-RED, downstream devices, storage, or physical interfaces are healthy. Continue to publish health separately.

---

# Suggested server-to-gateway and gateway-to-server methods

## Server calls gateway

```text
system.health.get
system.snapshot.get

agent.pause
agent.resume
agent.reload
agent.reset

config.get
config.apply
runtimeConfig.list
runtimeConfig.set

service.list
service.register
service.remove

device.list
device.register
device.remove
device.markSeen
device.interface.open
device.interface.close
device.interface.read
device.interface.write

backup.create
backup.restore

nodeRed.status.get
nodeRed.flows.get
nodeRed.flows.deploy
nodeRed.action.execute

firmware.update.start
firmware.update.abort
firmware.update.status.get

log.stream.open
terminal.open

job.get
job.cancel
```

## Gateway calls server

```text
bootstrap.enroll
credential.certificate.renew
configuration.initial.get
configuration.secret.resolve
artifact.downloadAuthorization.get
release.latest.get
service.endpoint.resolve
support.incident.open
```

The server should expose logical services, not one monolithic “server” endpoint:

```text
svc/bootstrap
svc/provisioning
svc/artifacts
svc/releases
svc/support
svc/credentials
```

That permits independent scaling, shared subscriptions, and narrower authorization.

---

# OpenRPC and AsyncAPI artifacts

Maintain two machine-readable contracts.

## OpenRPC document

Defines:

* Method names.
* Parameter schemas.
* Result schemas.
* Error codes.
* Idempotency classification.
* Required capability.
* Required authorization class.
* Maximum expected duration.
* Whether the method returns a job.

Example extension:

```json
{
  "name": "firmware.update.start",
  "x-operation-class": "durable-job",
  "x-idempotency": "request-id",
  "x-required-role": "firmware-admin",
  "x-default-expiry-seconds": 30
}
```

## AsyncAPI document

Defines:

* Request and response topics.
* MQTT 5 bindings.
* Correlation Data location.
* Response Topic rules.
* Telemetry channels.
* Desired/reported state.
* Job events.
* Stream topics.
* Payload schemas.
* Authentication and authorization requirements.

This provides a usable source for:

* Gateway/server client generation.
* Schema validation.
* Contract tests.
* Documentation.
* Compatibility checking.
* Test simulators.

---

# Recommended migration from your current local UI

## Phase 1 — MQTT transport and security

* Introduce MQTT 5.
* Assign unique gateway identities.
* Enable mTLS.
* Implement topic ACLs and quotas.
* Add presence and capability reporting.
* Keep the current local UI unchanged.

## Phase 2 — RPC adapter

Create an RPC dispatcher inside the gateway that calls the same internal service methods currently used by the local HTTP handlers.

Start with:

* Health and snapshot reads.
* Configuration reads.
* Service and device lists.
* Pause/resume/reload.
* Basic device actions.

This avoids maintaining two separate implementations of gateway behavior.

## Phase 3 — State and events

* Add desired/reported configuration.
* Replace local WebSocket change semantics with MQTT events.
* Add telemetry publication.
* Add configuration revision and generation handling.

## Phase 4 — Durable jobs and artifacts

Convert:

* OTA.
* Backup.
* Restore.
* Reset.
* Node-RED deploy.
* Large configuration apply.

Use HTTPS artifact transfer and MQTT job control.

## Phase 5 — Streams

* Add log-stream sessions.
* Add terminal sessions.
* Add limits, sequence numbers, expiry, and privileged authorization.

## Phase 6 — Bootstrap and certificate lifecycle

* Add factory identity.
* Add enrollment.
* Add operational certificate issuance.
* Add renewal, revocation, quarantine, and decommissioning.
* Add signed firmware and anti-rollback policy.

---

# Final decision

Adopt this as your gateway-management protocol:

> **MQTT 5 Request/Response + JSON-RPC 2.0 + OpenRPC, documented with AsyncAPI 3.1.**

Use it as a symmetric RPC profile: both the server and gateway may publish requests and supply Response Topics.

Do not model the entire remote-management system as RPC. Divide it into:

1. **RPC** for short operations.
2. **Durable jobs** for OTA, restore, reset, backup, and deployment.
3. **Desired/reported state and events** for configuration, status, and telemetry.
4. **Bounded streams** for logs and terminal.

Choose **BBF USP/TR-369 Issue 1 Amendment 5** instead only when standardized broadband/CPE management and TR-181 interoperability justify its larger Agent/Controller and data-model architecture. For arbitrary gateway-to-server calls under USP, deploy dual Agent/Controller roles or maintain a supplementary reverse-RPC channel.

[1]: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.pdf "MQTT Version 5.0"
[2]: https://www.jsonrpc.org/specification "JSON-RPC 2.0 Specification"
[3]: https://spec.open-rpc.org/ "OpenRPC Specification | spec"
[4]: https://usp.technology/specification/ "BBF – TR-369 – The User Services Platform"
[5]: https://www.openmobilealliance.org/release/lightweightm2m/V1_2_2-20240613-A/HTML-Version/OMA-TS-LightweightM2M_Core-V1_2_2-20240613-A.html "OMA-TS-LightweightM2M_Core-V1_2_2-20240613-A_full"
[6]: https://www.openmobilealliance.org/release/lightweightm2m/V1_2_2-20240613-A/OMA-TS-LightweightM2M_Transport-V1_2_2-20240613-A.pdf "OMA-TS-LightweightM2M_Transport-V1_2_2-20240613-A_full"
[7]: https://sparkplug.eclipse.org/specification/version/3.0/documents/sparkplug-specification-3.0.0.pdf "Sparkplug 3.0.0: Sparkplug Specification"
[8]: https://www.w3.org/TR/wot-thing-description11/ "Web of Things (WoT) Thing Description 1.1"
[9]: https://www.rfc-editor.org/rfc/rfc8259.html "www.rfc-editor.org"
[10]: https://www.rfc-editor.org/rfc/rfc9562.html "RFC 9562: Universally Unique IDentifiers (UUIDs)"
[11]: https://www.rfc-editor.org/info/rfc9019 "RFC 9019: A Firmware Update Architecture for Internet of Things | RFC Editor"
[12]: https://www.rfc-editor.org/info/rfc8995/?utm_source=chatgpt.com "RFC 8995: Bootstrapping Remote Secure Key ..."
[13]: https://www.rfc-editor.org/rfc/rfc9325.html "RFC 9325: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)"
