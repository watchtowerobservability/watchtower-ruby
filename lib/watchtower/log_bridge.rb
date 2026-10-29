# frozen_string_literal: true

require 'logger'

module Watchtower
  # Wraps a Logger: every record also becomes a "log" event on the current span (so logs sit on the
  # trace), redacted by the configured hook.
  # shortcut: span events, not the OTLP logs signal; move to opentelemetry-logs-sdk when stable.
  class LogBridge < ::Logger
    LABELS = %w[DEBUG INFO WARN ERROR FATAL ANY].freeze

    def initialize(inner)
      super(nil)
      @inner = inner
    end

    def add(severity, message = nil, progname = nil, &block)
      severity ||= ::Logger::UNKNOWN
      message = block.call if message.nil? && block
      message = progname if message.nil?
      @inner.add(severity, message, progname)
      span = OpenTelemetry::Trace.current_span
      if span.context.valid? && severity >= level
        attrs = { 'log.severity' => LABELS[severity] || 'ANY', 'log.message' => message.to_s }
        span.add_event('log', attributes: Watchtower.redact(attrs, Watchtower.redactor))
      end
      true
    end
  end
end
