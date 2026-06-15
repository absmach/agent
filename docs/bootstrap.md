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
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_DOMAIN_ID="<domain-id>"
export MG_PAT="<personal-access-token>"
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
export MG_API="https://cloud.magistrala.absmach.eu/api"
export MG_AGENT_MQTT_URL=ssl://messaging.magistrala.absmach.eu:8883
export MG_AGENT_MQTT_SKIP_TLS=false
export MG_AGENT_BOOTSTRAP_EXTERNAL_ID="<device-external-id>"
export MG_AGENT_BOOTSTRAP_EXTERNAL_KEY="<device-external-key>"
export MG_DOMAIN_ID="<domain-id>"
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
  "id": "fa846d56-3100-44aa-8385-3a88cb437a5a",
  "content": "{\n  \"commands\": {\n    \"channel_id\": \"bc9a0af7-6d0f-4806-aa5a-61d68c0a7cf7\"\n  },\n  \"device_id\": \"fa846d56-3100-44aa-8385-3a88cb437a5a\",\n  \"domain_id\": \"e9692c28-b730-4797-8a15-2e25c08f9641\",\n  \"external_id\": \"019eb690777d7452ba898a66f5cc9cb8\",\n  \"mqtt\": {\n    \"client_id\": \"ffec2491-0de1-4051-9e75-ad2e2d241627\",\n    \"secret\": \"30c775d7-3504-42c6-976c-52c02474bf2f\",\n    \"url\": \"ssl://host.docker.internal:8883\"\n  },\n  \"provision\": {\n    \"channels_url\": \"http://channels:9005\",\n    \"clients_url\": \"http://clients:9006\",\n    \"rules_engine_url\": \"http://rules:9008\",\n    \"token\": \"pat_TurQa8bRR72vtZguCtIIe8ZTeaSkqkinkhLxSqPo7bw=_PoOG@UuEadfD!F7TcWYzsDKSxLB%3mzlh1M\\u0026MmLIky0M8A2Ui9f9J^4DuzZ@O0rjCA-cvgjbuFjOofOwreHL-j\\u0026CcgffH7FzwoDC\"\n  },\n  \"telemetry\": {\n    \"channel_id\": \"b465a688-c1ca-417d-a36f-71f6f1be2409\",\n    \"topic\": \"\\u003cno value\\u003e\"\n  }\n}"
}
```

### Force a bootstrap re-fetch at runtime

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
    -m '[{"bn":"req-1:", "n":"config", "vs":"set,bs_valid,0"}]'
```

This sets `bs_valid` to `0` and deletes the cached bootstrap profile. On the **next restart**, the agent will re-fetch the profile from the bootstrap service.

### Check bootstrap cache status

```bash
mosquitto_pub \
    -h <mqtt-host> -p 1883 \
    -u <client-id> -P <client-secret> --id "cfg-$(date +%s)" \
    -t "m/<domain-id>/c/<commands-channel-id>/req" \
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
