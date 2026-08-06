# Wazuh Incident Sidecar

A small service that receives Wazuh alerts, creates an LLM-assisted incident report for alerts at a chosen severity, and publishes those reports to a Discord incoming webhook.

## Run it

```powershell
Copy-Item .env.example .env
# edit .env and set INGEST_API_KEY, DISCORD_WEBHOOK_URL, and LLM credentials
docker compose up --build -d
```

The service listens on port `8080`.

## Configure Wazuh delivery

Use a Wazuh integration or a small custom script to POST every alert JSON to:

```text
http://YOUR-SIDECAR:8080/v1/alerts
```

with these headers:

```text
Content-Type: application/json
X-API-Key: your-INGEST_API_KEY
```

The endpoint accepts normal Wazuh alert objects (including `rule.level`, `rule.description`, `agent`, `data`, and `full_log`). It also accepts `{"alerts": [...]}` for batches.

An integration helper is provided in `integrations/custom-wazuh-sidecar`. On the Wazuh manager, copy it into `/var/ossec/integrations/` with that exact extensionless name, make it executable and owned by `root:wazuh`, then add an integration block like this to `/var/ossec/etc/ossec.conf` (replace the key and URL):

```xml
<integration>
  <name>custom-wazuh-sidecar</name>
  <level>0</level>
  <alert_format>json</alert_format>
  <hook_url>http://sidecar.internal:8080</hook_url>
  <api_key>replace-with-your-ingest-key</api_key>
</integration>
```

Restart the Wazuh manager after updating its configuration. The integration script receives the Wazuh-managed `hook_url` and `api_key` arguments.

## Behavior

- Alerts below `REPORT_MIN_SEVERITY` are stored but do not open a report.
- Alerts at or above the threshold are summarized by the configured OpenAI-compatible model and dispatched to Discord.
- If LLM setup is omitted or unavailable, the service still produces a deterministic report from the Wazuh fields.
- Duplicate alerts (same Wazuh alert `id`) are ignored.

## Useful endpoints

- `GET /health` — readiness and configuration state
- `POST /v1/alerts` — ingest one alert or an `alerts` array
- `GET /v1/alerts?limit=50` — recent alerts
- `GET /v1/reports?limit=50` — recent generated reports

## Security notes

Keep the ingest endpoint on a private network or behind a reverse proxy. Always set a strong `INGEST_API_KEY`, and keep `.env` out of source control.
