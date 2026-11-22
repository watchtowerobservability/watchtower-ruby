# frozen_string_literal: true

require 'logger'

module Watchtower
  # Wraps a Logger. With the OTLP logs signal on (Watchtower.init, WATCHTOWER_LOGS) every record
  # also becomes an OpenTelemetry log record through the logs API, carrying the current trace and
  # span ids; with it off the record is added as a "log" event on the current span instead. Both
  # are redacted by the configured hook.
  class LogBridge < ::Logger
    LABELS = %w[DEBUG INFO WARN ERROR FATAL ANY].freeze
    SEVERITY = [5, 9, 13, 17, 21, 0].freeze # OTel severity numbers of DEBUG..UNKNOWN

    def initialize(inner)
      super(nil)
      @inner = inner
    end

    def add(severity, message = nil, progname = nil, &block)
      severity ||= ::Logger::UNKNOWN
      message = block.call if message.nil? && block
      message = progname if message.nil?
      @inner.add(severity, message, progname)
      return true if severity < level

      locs = caller_locations(1, 12)

      if Watchtower.logs?
        emit(severity, message, progname, locs)
      else
        span = OpenTelemetry::Trace.current_span
        if span.context.valid?
          attrs = { 'log.severity' => LABELS[severity] || 'ANY', 'log.message' => message.to_s }
          span.add_event('log', attributes: Watchtower.redact(attrs, Watchtower.redactor))
        end
      end
      true
    end

    private

    # File and line of the code that called the logger (first frame outside this file and the stdlib logger).
    def self.caller_attrs(locs = caller_locations(2, 12))
      loc = (locs || []).find { |l| l.absolute_path != __FILE__ && !l.path.end_with?('/logger.rb') }
      loc ? { 'code.filepath' => loc.absolute_path || loc.path, 'code.lineno' => loc.lineno } : {}
    end

    def emit(severity, message, progname, locs)
      attrs = { 'log.message' => message.to_s }.merge(LogBridge.caller_attrs(locs))
      attrs['log.logger'] = progname.to_s unless progname.nil? || progname == message
      attrs = Watchtower.redact(attrs, Watchtower.redactor)
      body = attrs.delete('log.message').to_s
      # the SDK logger takes the trace and span ids from the current context
      OpenTelemetry.logger_provider.logger(name: 'watchtower').on_emit(
        timestamp: Time.now, severity_number: SEVERITY[severity] || 0, severity_text: LABELS[severity] || 'ANY',
        body: body, attributes: attrs
      )
    end
  end
end
