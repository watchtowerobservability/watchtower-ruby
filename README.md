# watchtower-sdk (Ruby)

[![CI](https://github.com/watchtowerobservability/watchtower-ruby/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-ruby/actions/workflows/ci.yml)

Thin Watchtower distribution over the OpenTelemetry Ruby SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook, offline buffer, error capture with trace ids, and Rails, Sidekiq, Rack and Logger integrations.

Status: 0.x, early. APIs may change between minor versions.

## Install

```ruby
# Gemfile
source 'https://rubygems.pkg.github.com/watchtowerobservability' do
  gem 'watchtower-sdk'
end
gem 'opentelemetry-instrumentation-all' # optional: Rack, Rails, Sidekiq, ActiveRecord, Net::HTTP spans
```

## Quick start

```ruby
require 'watchtower'
Watchtower.init(Watchtower::Config.from_env)   # reads WT_INGEST_KEY, WT_SERVICE, ...
Watchtower.install_exception_hooks             # captures the exception that ends the process
Watchtower.capture_exception(e)                # => { trace_id:, span_id: }
```

The ingest key is read from the environment (`WT_INGEST_KEY`); never commit it.

## Integrations

| Integration | Setup |
| --- | --- |
| Rails | `require 'watchtower'` in an initializer; the railtie inserts the Rack middleware, subscribes to `Rails.error`, and captures ActiveJob and ActionCable failures |
| Rack (Sinatra, Hanami, ...) | `use Watchtower::RackMiddleware` |
| Sidekiq | `config.server_middleware { |m| m.add Watchtower::SidekiqMiddleware }` |
| sqlite3 | `require 'watchtower/sqlite3'; Watchtower::SQLite3.instrument`: statement spans with `db.query.hash` and `db.query.summary`, no values (`with_text: true` adds sanitized text) |
| Logger | `logger = Watchtower::LogBridge.new(Logger.new($stdout))` sends each record as an OTLP log record with the current trace and span ids (a `log` span event when logs are off) |
| Metrics | `OpenTelemetry.meter_provider.meter('app').create_counter('jobs').add(1)`; `init` installs a periodic OTLP reader (delta temporality unless `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` is set; `OTEL_METRIC_EXPORT_INTERVAL` sets the period). Ruby has no official runtime metrics package yet |
| Other libraries | enabled by `opentelemetry-instrumentation-all` when installed (`Watchtower.init(cfg, instrument: false)` to skip) |

## Profiling

```ruby
require 'watchtower/profiling'
Watchtower::Profiler.new(service: 'api').start   # key and endpoint from WT_INGEST_KEY / WT_OTLP_ENDPOINT
```

A plain-Ruby wall-clock sampler (100 Hz, every thread's backtrace) posts folded stacks to the
gateway's `/ingest` every 15 s as `<service>.wall`. Inside `Watchtower::Profiler.with_span { ... }`
samples carry the current OpenTelemetry span (fiber-local, so it follows fibers of the async gem), so a trace links to its exact
profile. For native CPU frames run rbspy against `/ingest` instead.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `WT_INGEST_KEY` | none | secret ingest key, sent as `Authorization: Bearer` |
| `WT_OTLP_ENDPOINT` | `http://localhost:4318` | OTLP/HTTP base URL (`WT_ENDPOINT` is a deprecated alias) |
| `WT_SERVICE` | `unknown_service` | `service.name` |
| `WT_ENVIRONMENT` | none | `deployment.environment` |
| `WT_RELEASE` | none | `service.version` |
| `WATCHTOWER_LOGS` | `on` | `off` stops OTLP logs (`OTEL_LOGS_EXPORTER=none` too) |
| `WATCHTOWER_METRICS` | `on` | `off` stops OTLP metrics (`OTEL_METRICS_EXPORTER=none` too) |
| `WT_SPOOL_DIR` | none | file spool for traces (root), logs (`logs/`) and metrics (`metrics/`), 500 batches each |

Pass `redactor: ->(key, value) { ... }` to `Config` to mask (return a value) or drop (return nil) attributes.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-ruby`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
