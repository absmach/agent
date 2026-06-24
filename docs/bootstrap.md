# Bootstrap

The bootstrap subsystem handles profile-based provisioning. At startup, the agent fetches a rendered bootstrap profile from the Magistrala Bootstrap service, which provides device identity, MQTT credentials, channel IDs, and provision configuration. The profile is cached locally so subsequent starts skip the HTTP fetch.

## Bootstrap Flow

1. **Agent starts** with `MG_AGENT_BOOTSTRAP_URL`, `MG_AGENT_BOOTSTRAP_EXTERNAL_ID`, and `MG_AGENT_BOOTSTRAP_EXTERNAL_KEY` set.
2. **Check cache** — if bootstrap-derived fields are already in the persistent config store and `bs_valid` is `1`, skip the HTTP fetch.
3. **Fetch profile** — HTTP GET to the bootstrap endpoint with the external ID and key.
4. **Parse content** — the bootstrap response wraps a JSON string in `content`:
   ```json
   {
     "content": "{ \"device_id\": \"...\", \"mqtt\": { ... } }",
     "gateway_key": "",
     "gateway_cert": "",
     "ca_cert": ""
   }
   ```
5. **Merge with env config** — bootstrap fields override env defaults for `tenant_id`, `channels`, and `mqtt`.
6. **Persist** — bootstrap fields are saved to the persistent config store (`agent-config.json`).
7. **Load certificates** — if mTLS is configured, gateway and CA certs are loaded.
8. **Connect MQTT** — the agent connects using the bootstrap-provided credentials.

## Rendered Profile Content

The `content` field from the bootstrap response decodes to:

```json
{
  "device_id": "<gateway-id>",
  "external_id": "<external-id>",
  "tenant_id": "<tenant-id>",
  "mqtt": {
    "url": "ssl://host.docker.internal:8883",
    "client_id": "<gateway-id>",
    "secret": "<gateway-secret>"
  },
  "telemetry": {
    "channel_id": "<telemetry-channel-id>",
    "topic": "m/<tenant-id>/c/<telemetry-channel-id>/msg"
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
| `tenant_id`        | Bootstrap profile                   |
| `channels_ctrl_id` | Bootstrap profile                   |
| `channels_data_id` | Bootstrap profile                   |
| `mqtt_url`         | Bootstrap profile                   |
| `mqtt_username`    | Bootstrap profile                   |
| `mqtt_password`    | Bootstrap profile                   |
| `bs_valid`         | Set to `"1"` after successful fetch |

## Provisioning

### Automated (recommended)

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_TENANT_ID="<tenant-id>"
export MG_PAT="<personal-access-token>"
make run_provision
```

The provisioning script creates:

1. A Gateway with credentials
2. Telemetry and commands Channels
3. A Bootstrap Profile and Enrollment with `external_id` and `external_key`
4. Profile bindings to the provisioned gateway and channels
5. A Rule Engine rule with `save_senml` output for telemetry

### Cloud provisioning

```bash
export MG_API="https://cloud.magistrala.absmach.eu/api"
export MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883
export MG_AGENT_MQTT_SKIP_TLS=false
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_TENANT_ID="<tenant-id>"
export MG_PAT="<pat>"
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
  "id": "<gateway-entity-id>",
  "content": "{\n  \"commands\": {\n    \"channel_id\": \"<commands-channel-id>\"\n  },\n  \"device_id\": \"<gateway-entity-id>\",\n  \"tenant_id\": \"<tenant-id>\",\n  \"external_id\": \"<external-id>\",\n  \"mqtt\": {\n    \"client_id\": \"<gateway-entity-id>\",\n    \"secret\": \"<client-secret>\",\n    \"url\": \"ssl://host.docker.internal:8883\"\n  },\n  \"provision\": {\n    \"channels_url\": \"http://channels:9005\",\n    \"clients_url\": \"http://clients:9006\",\n    \"rules_engine_url\": \"http://rules:9008\",\n    \"token\": \"<personal-access-token>\"\n  },\n  \"telemetry\": {\n    \"channel_id\": \"<telemetry-channel-id>\",\n    \"topic\": \"m/<tenant-id>/c/<telemetry-channel-id>/msg\"\n  }\n}"
}
```

### Force a bootstrap re-fetch at runtime

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "cfg-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,bs_valid,0"}]'
```

This sets `bs_valid` to `0` and deletes the cached bootstrap profile. On the **next restart**, the agent will re-fetch the profile from the bootstrap service.

### Check bootstrap cache status

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <gateway-id> -P <gateway-secret> --id "cfg-$(date +%s)" \
    -t "m/<tenant-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"get,bs_valid"}]'
```

**Response:** `1` (valid cache) or `0` (cache invalidated).

### Run agent without Docker

```bash
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<external-key>"
export MG_AGENT_BOOTSTRAP_URL="http://localhost:9013/clients/bootstrap"
build/magistrala-agent
```

### Verify agent startup logs

After a successful bootstrap fetch, the agent logs:

```json
{"level":"INFO","msg":"Gateway connected","gateway_name":"<gateway-id>"}
{"level":"INFO","msg":"Agent service started","port":"9999"}
```

If bootstrap data is already cached:

```json
{
  "level": "INFO",
  "msg": "Bootstrap data already present, skipping bootstrap fetch"
}
```
