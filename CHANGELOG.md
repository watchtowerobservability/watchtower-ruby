# Changelog

## 0.1.0

- Init over OpenTelemetry Ruby: key header, endpoint default, offline buffer, redaction hook.
- `capture_exception` with trace and span ids, process-exit hook.
- Rails railtie (`Rails.error`, ActiveJob, ActionCable), Sidekiq and Rack middleware, Logger bridge.
- Config from `WT_OTLP_ENDPOINT` (`WT_ENDPOINT` deprecated alias), `WT_SERVICE`, `WT_ENVIRONMENT`, `WT_RELEASE`.
