# watchtower-sdk

Thin Watchtower distribution over the OpenTelemetry Ruby SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook, offline buffer.

Status: 0.x, early. APIs may change between minor versions.

## Install

```ruby
# Gemfile
source 'https://rubygems.pkg.github.com/watchtowerobservability' do
  gem 'watchtower-sdk'
end
```

## Use

```ruby
require 'watchtower'
Watchtower.init(Watchtower::Config.from_env(service: 'checkout'))
```

The ingest key is read from the environment (`WT_INGEST_KEY`); never commit it.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-ruby`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
