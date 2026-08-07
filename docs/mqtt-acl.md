# MQTT Topic Permissions

Use a different operational identity for the Agent and Agent Gateway. The
control and data channels must be separately provisioned.

## Agent identity

| Action | Topic |
| --- | --- |
| Subscribe | `m/{domain}/c/{control}/req` |
| Subscribe | `m/{domain}/c/{control}/gateway/state/desired` |
| Subscribe | `m/{domain}/c/{control}/gateway/streams/+/control` |
| Subscribe | `m/{domain}/c/{control}/gateway/streams/+/in` |
| Subscribe | `m/{domain}/c/{control}/service/+/res/{agentId}/{bootId}` |
| Publish | `m/{domain}/c/{control}/res/+` |
| Publish | `m/{domain}/c/{control}/service/+/req` |
| Publish | `m/{domain}/c/{data}/gateway/#` |

## Agent Gateway identity

| Action | Topic |
| --- | --- |
| Publish | `m/{domain}/c/{control}/req` |
| Publish | `m/{domain}/c/{control}/gateway/state/desired` |
| Publish | `m/{domain}/c/{control}/gateway/streams/+/control` |
| Publish | `m/{domain}/c/{control}/gateway/streams/+/in` |
| Publish | `m/{domain}/c/{control}/service/+/res/+/#` |
| Subscribe | `m/{domain}/c/{control}/res/{gatewayClientId}` |
| Subscribe | `m/{domain}/c/{control}/service/+/req` |
| Subscribe | `m/{domain}/c/{data}/gateway/#` |

Magistrala channel connection grants are the coarse resource boundary. If the
broker cannot enforce publish/subscribe direction below the channel, use
separate service identities and a broker authorization hook that applies the
topic rules above. Do not give a browser either identity.

At minimum, contract tests must prove that an identity cannot access another
Agent's channels or substitute an arbitrary MQTT Response Topic.
