require 'watchtower'

Watchtower.init(Watchtower::Config.from_env(service: 'example-ruby'))
OpenTelemetry.tracer_provider.tracer('example').in_span('hello') {}
OpenTelemetry.tracer_provider.shutdown # flush before exit
