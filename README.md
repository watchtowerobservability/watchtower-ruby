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
| Logger | `logger = Watchtower::LogBridge.new(Logger.new($stdout))` adds each record as a `log` event on the current span |
| Other libraries | enabled by `opentelemetry-instrumentation-all` when installed (`Watchtower.init(cfg, instrument: false)` to skip) |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `WT_INGEST_KEY` | none | secret ingest key, sent as `Authorization: Bearer` |
| `WT_OTLP_ENDPOINT` | `http://localhost:4318` | OTLP/HTTP base URL (`WT_ENDPOINT` is a deprecated alias) |
| `WT_SERVICE` | `unknown_service` | `service.name` |
| `WT_ENVIRONMENT` | none | `deployment.environment` |
| `WT_RELEASE` | none | `service.version` |

Pass `redactor: ->(key, value) { ... }` to `Config` to mask (return a value) or drop (return nil) attributes.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-ruby`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
