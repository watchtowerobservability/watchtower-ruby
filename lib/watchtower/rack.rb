# frozen_string_literal: true

module Watchtower
  # Rack middleware: captures raised exceptions and ones a framework rescued into the env
  # (Rails ShowExceptions, Sinatra), then re-raises.
  class RackMiddleware
    ENV_KEYS = %w[action_dispatch.exception sinatra.error rack.exception].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      req = Payload.active? ? read_input(env) : nil
      response = @app.call(env)
      ENV_KEYS.each { |k| Watchtower.capture_exception(env[k], 'http.route' => env['PATH_INFO']) if env[k] }
      capture_payload(env, req, response) if req
      response
    rescue Exception => e # rubocop:disable Lint/RescueException
      Watchtower.capture_exception(e, 'http.route' => env['PATH_INFO'])
      raise
    end

    private

    # Up to 2 * HARD_MAX bytes of a rewindable input, rewound for the app; '' when unreadable.
    def read_input(env)
      io = env['rack.input']
      return '' unless io.respond_to?(:rewind)

      data = io.read(Payload::HARD_MAX * 2) || ''
      io.rewind
      data
    end

    # Response bodies are read only when a plain Array (to_ary on a BodyProxy would close it).
    def capture_payload(env, req, response)
      _status, headers, body = response
      res = body.is_a?(Array) ? body.join.byteslice(0, Payload::HARD_MAX * 2) : nil
      route = env['action_dispatch.route_uri_pattern'] || env['PATH_INFO']
      type = headers && (headers['content-type'] || headers['Content-Type'])
      Payload.record(OpenTelemetry::Trace.current_span, route.to_s.sub(/\(\.:format\)\z/, ''),
                     env['CONTENT_TYPE'], req, type, res)
    rescue StandardError
      nil # capture must never break the response
    end
  end
end
