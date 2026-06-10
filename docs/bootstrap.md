# Bootstrap

The bootstrap subsystem handles profile-based provisioning. At startup, the agent fetches a rendered bootstrap profile from the Magistrala Bootstrap service, which provides device identity, MQTT credentials, channel IDs, and provision configuration. The profile is cached locally so subsequent starts skip the HTTP fetch.

## Overview

```
┌──────────────┐   1. GET /clients/bootstrap   ┌──────────────┐
│    Agent     │ ─────────────────────────────── │  Bootstrap   │
│   (startup)  │ ◄─── rendered profile JSON ──── │   Service    │
└──────┬───────┘                                └──────────────┘
       │
       │ 2. Extract device_id, domain_id,
       │    mqtt credentials, channel IDs
       │
       │ 3. Connect to MQTT broker
       ▼
┌──────────────┐
│  MQTT Broker │
│ (Magistrala) │
└──────────────┘
```

## Bootstrap Flow

1. **Agent starts** with `MG_AGENT_BOOTSTRAP_URL`, `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`, and `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` set.
2. **Check cache** — if bootstrap-derived fields are already in the persistent config store and `bs_valid` is `1`, skip the HTTP fetch.
3. **Fetch profile** — HTTP GET to the bootstrap endpoint with the external ID and key.
4. **Parse content** — the bootstrap response wraps a JSON string in `content`:
   ```json
   {
     "content": "{ \"device_id\": \"...\", \"mqtt\": { ... } }",
     "client_key": "",
     "client_cert": "",
     "ca_cert": ""
   }
   ```
5. **Merge with env config** — bootstrap fields override env defaults for `domain_id`, `channels`, and `mqtt`.
6. **Persist** — bootstrap fields are saved to the persistent config store (`agent-config.json`).
7. **Load certificates** — if mTLS is configured, client and CA certs are loaded.
8. **Connect MQTT** — the agent connects using the bootstrap-provided credentials.

## Rendered Profile Content

The `content` field from the bootstrap response decodes to:

```json
{
  "device_id": "<client-id>",
  "external_id": "<external-id>",
  "domain_id": "<domain-id>",
  "mqtt": {
    "url": "ssl://host.docker.internal:8883",
    "client_id": "<client-id>",
    "secret": "<client-secret>"
  },
  "telemetry": {
    "channel_id": "<telemetry-channel-id>",
    "topic": "m/<domain-id>/c/<telemetry-channel-id>/msg"
  },
  "commands": {
    "channel_id": "<commands-channel-id>"
  }
}
```

## Configuration

### Environment Variables

| Variable                                 | Default                         | Description                                                                 |
| ---------------------------------------- | ------------------------------- | --------------------------------------------------------------------------- |
| `MG_AGENT_BOOTSTRAP_URL`                 | `""`                            | Bootstrap service base URL (e.g. `http://bootstrap:9013/clients/bootstrap`) |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`         | `""`                            | Device external ID used to look up the profile                              |
| `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY`        | `""`                            | Device external key (sent as `Authorization: Client <key>`)                 |
| `MG_AGENT_BOOTSTRAP_RETRIES`             | `5`                             | Number of retries when fetching bootstrap profile                           |
| `MG_AGENT_BOOTSTRAP_RETRY_DELAY_SECONDS` | `10`                            | Delay between retries in seconds                                            |
| `MG_AGENT_BOOTSTRAP_SKIP_TLS`            | `false`                         | Skip TLS verification for bootstrap HTTP fetch                              |
| `MG_AGENT_BOOTSTRAP_CACHE_PATH`          | `/var/lib/agent/bootstrap.json` | Local file path for caching the bootstrap response                          |

### When Bootstrap Is Active

Bootstrap mode activates when **all three** are set:

- `MG_AGENT_BOOTSTRAP_URL`
- `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`
- `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY`

When bootstrap is active, the legacy `config.toml` file is ignored.

### Persistent Config Store

| Variable               | Default             | Description                                                |
| ---------------------- | ------------------- | ---------------------------------------------------------- |
| `MG_AGENT_CONFIG_PATH` | `agent-config.json` | Path to the JSON file used for persistent config overrides |

Bootstrap-derived fields persisted in the store:

| Key                | Source                              |
| ------------------ | ----------------------------------- |
| `domain_id`        | Bootstrap profile                   |
| `channels_ctrl_id` | Bootstrap profile                   |
| `channels_data_id` | Bootstrap profile                   |
| `mqtt_url`         | Bootstrap profile                   |
| `mqtt_username`    | Bootstrap profile                   |
| `mqtt_password`    | Bootstrap profile                   |
| `bs_valid`         | Set to `"1"` after successful fetch |

## Provisioning

### Automated (recommended)

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID='01:6:0:sb:sa'
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY='secret'
export MG_DOMAIN_ID=<domain-id>
export MG_PAT=<personal-access-token>
make run_provision
```

The provisioning script creates:

1. A Client (device) with credentials
2. Telemetry and commands Channels
3. A Bootstrap Profile and Enrollment with `external_id` and `external_key`
4. Profile bindings to the provisioned client and channels
5. A Rule Engine rule with `save_senml` output for telemetry

### Cloud provisioning

```bash
MG_API=https://cloud.magistrala.absmach.eu/api \
MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883 \
MG_AGENT_MQTT_SKIP_TLS=false \
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<device-external-id> \
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<device-external-key> \
MG_DOMAIN_ID=<domain-id> \
MG_PAT=<pat> \
make run_provision
```

## Test Recipes

### Fetch the bootstrap profile manually

```bash
curl -s 'http://localhost:9013/clients/bootstrap/<external-id>' \
  -H 'accept: */*' \
  -H 'Authorization: Client <external-key>'
```

**Expected response:**

```json
{
  "content": "{\"device_id\":\"...\",\"external_id\":\"...\",\"domain_id\":\"...\",\"mqtt\":{...},\"telemetry\":{...},\"commands\":{...}}",
  "client_key": "",
  "client_cert": "",
  "ca_cert": ""
}
```

### Force a bootstrap re-fetch at runtime

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"set,bs_valid,0"}]'
```

This sets `bs_valid` to `0` and deletes the cached bootstrap profile. On the **next restart**, the agent will re-fetch the profile from the bootstrap service.

### Check bootstrap cache status

```bash
mosquitto_pub \
  -h <mqtt-host> -p 8883 --capath /etc/ssl/certs \
  -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
  -t "m/<domain-id>/c/<commands-channel-id>/req" \
  -m '[{"bn":"req-1:", "n":"config", "vs":"get,bs_valid"}]'
```

**Response:** `1` (valid cache) or `0` (cache invalidated).

### Run agent without Docker

```bash
MG_AGENT_BOOTSTRAP_EXTERNAL_ID=<external-id> \
MG_AGENT_BOOTSTRAP_EXTERNAL_KEY=<external-key> \
MG_AGENT_BOOTSTRAP_URL=http://localhost:9013/clients/bootstrap \
build/magistrala-agent
```

### Verify agent startup logs

After a successful bootstrap fetch, the agent logs:

```json
{"level":"INFO","msg":"Client connected","client_name":"<client-id>"}
{"level":"INFO","msg":"Agent service started","port":"9999"}
```

If bootstrap data is already cached:

```json
{
  "level": "INFO",
  "msg": "Bootstrap data already present, skipping bootstrap fetch"
}
```

## Troubleshooting

| Symptom                                                    | Cause                                              | Fix                                                                                                      |
| ---------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Agent exits with `"bootstrap configuration is incomplete"` | Missing one of the three bootstrap env vars        | Set all of `MG_AGENT_BOOTSTRAP_URL`, `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`, `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` |
| Agent exits with `"Fetching bootstrap failed"`             | Bootstrap service unreachable or credentials wrong | Verify the bootstrap URL, external ID, and key; check network connectivity                               |
| Agent exits with `"missing required runtime fields"`       | Bootstrap profile is incomplete                    | Ensure the provisioning script created the profile with all required fields                              |
| Agent keeps re-fetching bootstrap on every restart         | `bs_valid` was set to `0` or cache file is missing | Check `MG_AGENT_BOOTSTRAP_CACHE_PATH` exists and is writable                                             |
| mTLS fails after bootstrap                                 | Client cert/key not in profile                     | Ensure the bootstrap profile includes `client_cert` and `ca_cert` fields                                 |
| `"Failed to persist domain_id"`                            | Config store file not writable                     | Check permissions on `MG_AGENT_CONFIG_PATH`                                                              |
