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
      response = @app.call(env)
      ENV_KEYS.each { |k| Watchtower.capture_exception(env[k], 'http.route' => env['PATH_INFO']) if env[k] }
      response
    rescue Exception => e # rubocop:disable Lint/RescueException
      Watchtower.capture_exception(e, 'http.route' => env['PATH_INFO'])
      raise
    end
  end
end
