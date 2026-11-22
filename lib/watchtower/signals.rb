# frozen_string_literal: true

module Watchtower
  # Logs and metrics over the official OpenTelemetry Ruby logs and metrics SDKs, exported over
  # OTLP/HTTP to the same endpoint with the same key as traces. Ruby has no official runtime
  # metrics instrumentation yet, so none is wired.
  module Signals
    OFF = %w[off false 0 no].freeze

    # Explicit flag, else `env` (on unless off/false/0/no); `otel_env=none` also turns it off.
    def self.on?(flag, env, otel_env)
      return flag unless flag.nil?
      return false if ENV.fetch(otel_env, '').strip.casecmp?('none')

      !OFF.include?(ENV.fetch(env, 'on').strip.downcase)
    end

    # Spools a failed batch (encoded by the official exporter) and replays the spool first.
    class SpoolingExporter
      def initialize(inner, spool, success)
        @inner = inner
        @spool = spool
        @success = success
      end

      def export(batch, timeout: nil)
        @spool.replay
        result = @inner.export(batch, timeout: timeout)
        @spool.push(batch) unless result == @success
        result
      end

      def force_flush(timeout: nil) = @inner.force_flush(timeout: timeout)
      def shutdown(timeout: nil) = @inner.shutdown(timeout: timeout)
    end

    def self.spooled(inner, config, signal, success)
      return inner unless config.spool_dir

      # `encode` is the exporter's own (private) OTLP protobuf encoder, so the spool needs no copy of it
      spool = FileSpool.new(File.join(config.spool_dir, signal), url: "#{config.endpoint}/v1/#{signal}",
                                                                  headers: config.headers,
                                                                  encode: ->(b) { inner.send(:encode, b) },
                                                                  content_type: 'application/x-protobuf')
      SpoolingExporter.new(inner, spool, success)
    end

    def self.start_logs(config, resource)
      require 'opentelemetry-logs-sdk'
      require 'opentelemetry-exporter-otlp-logs'
      exp = OpenTelemetry::Exporter::OTLP::Logs::LogsExporter.new(endpoint: "#{config.endpoint}/v1/logs",
                                                                  headers: config.headers)
      exp = spooled(exp, config, 'logs', OpenTelemetry::SDK::Logs::Export::SUCCESS)
      lp = OpenTelemetry::SDK::Logs::LoggerProvider.new(resource: resource)
      lp.add_log_record_processor(OpenTelemetry::SDK::Logs::Export::BatchLogRecordProcessor.new(exp))
      OpenTelemetry.logger_provider = lp
    end

    # Delta temporality for sums and histograms (our ingest default) unless
    # OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE is set; the SDK's aggregations read it.
    # OTEL_METRIC_EXPORT_INTERVAL sets the period.
    def self.start_metrics(config, resource)
      ENV['OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE'] ||= 'delta'
      require 'opentelemetry-metrics-sdk'
      require 'opentelemetry-exporter-otlp-metrics'
      klass = OpenTelemetry::Exporter::OTLP::Metrics::MetricsExporter
      opts = { endpoint: "#{config.endpoint}/v1/metrics", headers: config.headers }
      if klass.instance_method(:initialize).parameters.any? { |_, n| n == :aggregation_temporality }
        opts[:aggregation_temporality] = ENV.fetch('OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE')
      end
      exp = spooled(klass.new(**opts), config, 'metrics', OpenTelemetry::SDK::Metrics::Export::SUCCESS)
      mp = OpenTelemetry::SDK::Metrics::MeterProvider.new(resource: resource)
      mp.add_metric_reader(OpenTelemetry::SDK::Metrics::Export::PeriodicMetricReader.new(exporter: exp))
      OpenTelemetry.meter_provider = mp
    end
  end
end
