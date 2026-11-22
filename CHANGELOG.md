# Changelog

## 0.1.1

- Sync with the monorepo: log code location, in-app WAF and sqlite3 statement spans.

- Logs and metrics over the official OpenTelemetry Ruby logs and metrics SDKs (`opentelemetry-logs-sdk`, `opentelemetry-metrics-sdk` and their OTLP exporters), started by `init` and switched by `WATCHTOWER_LOGS` / `WATCHTOWER_METRICS` (or `Config` `logs:` / `metrics:`), default on. `LogBridge` now emits OTLP log records with trace and span ids. Metrics default to delta temporality. Failed log and metric batches spool to `WT_SPOOL_DIR/logs` and `/metrics` as OTLP protobuf.

- Offline file spool: `spool_dir:` / `WT_SPOOL_DIR` writes failed span batches as OTLP/JSON and resends them oldest first (`Watchtower::FileSpool`, at most 500 files).

## 0.1.0

- Init over OpenTelemetry Ruby: key header, endpoint default, offline buffer, redaction hook.
- `capture_exception` with trace and span ids, process-exit hook.
- Rails railtie (`Rails.error`, ActiveJob, ActionCable), Sidekiq and Rack middleware, Logger bridge.
- Config from `WT_OTLP_ENDPOINT` (`WT_ENDPOINT` deprecated alias), `WT_SERVICE`, `WT_ENVIRONMENT`, `WT_RELEASE`.
