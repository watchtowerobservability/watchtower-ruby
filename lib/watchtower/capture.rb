# frozen_string_literal: true

module Watchtower
  SEEN = ObjectSpace::WeakMap.new

  # Records the exception on the current span (or a new "exception" span) so the error links to its
  # trace. Returns { trace_id:, span_id: } (hex), or nil when not an exception or already captured.
  def self.capture_exception(error, attributes = {})
    return nil unless error.is_a?(Exception) && !SEEN.key?(error)

    SEEN[error] = true
    attrs = redact(attributes, redactor)
    span = OpenTelemetry::Trace.current_span
    return record(span, error, attrs) if span.context.valid?

    ids = nil
    OpenTelemetry.tracer_provider.tracer('watchtower').in_span('exception') { |s| ids = record(s, error, attrs) }
    ids
  end

  def self.record(span, error, attrs)
    span.record_exception(error, attributes: attrs)
    span.status = OpenTelemetry::Trace::Status.error(error.message.to_s[0, 200])
    { trace_id: span.context.hex_trace_id, span_id: span.context.hex_span_id }
  end

  # Captures the exception that ends the process; uncaught thread errors are reported by Ruby itself.
  def self.install_exception_hooks
    return if @hooks

    @hooks = true
    at_exit { capture_exception($!) if $! && !$!.is_a?(SystemExit) }
  end
end
