# frozen_string_literal: true

# Watchtower distribution of the OpenTelemetry Ruby SDK: key header, endpoint default,
# offline buffer, wt.*-safe resource attributes and a redaction hook. No product logic.
module Watchtower
  DEFAULT_ENDPOINT = 'http://localhost:4318'

  # Bounded buffer; drops the oldest item when full.
  # shortcut: in memory only, a process restart loses it; upgrade to a file spool.
  class OfflineBuffer
    def initialize(max = 64)
      @max = [max, 1].max
      @items = []
      @lock = Mutex.new
    end

    def push(item)
      @lock.synchronize do
        @items.shift if @items.size >= @max
        @items << item
      end
    end

    def drain
      @lock.synchronize { @items.slice!(0..) }
    end

    def size
      @lock.synchronize { @items.size }
    end
  end

  class Config
    attr_reader :service, :endpoint, :redactor, :resource

    def initialize(service:, endpoint: nil, key: nil, resource: {}, redactor: nil,
                   environment: nil, release: nil)
      @service = service
      @endpoint = (endpoint || DEFAULT_ENDPOINT).sub(%r{/+\z}, '')
      @key = key
      @resource = resource.dup
      @resource['deployment.environment'] ||= environment if environment
      @resource['service.version'] ||= release if release
      @redactor = redactor
    end

    def self.env(name)
      v = ENV.fetch(name, '')
      v.empty? ? nil : v
    end

    # WT_ENDPOINT is the deprecated alias of WT_OTLP_ENDPOINT.
    def self.from_env(service: nil, **opts)
      new(service: service || env('WT_SERVICE') || 'unknown_service',
          endpoint: env('WT_OTLP_ENDPOINT') || env('WT_ENDPOINT'), key: env('WT_INGEST_KEY'),
          environment: env('WT_ENVIRONMENT'), release: env('WT_RELEASE'), **opts)
    end

    def headers
      @key ? { 'authorization' => "Bearer #{@key}" } : {}
    end

    def resource_attributes
      { 'service.name' => @service }.merge(Watchtower.drop_reserved(@resource))
    end

    # The key must never reach logs.
    def inspect
      "#<Watchtower::Config service=#{@service.inspect} endpoint=#{@endpoint.inspect} key=***>"
    end
  end

  def self.reserved?(key)
    key.to_s.start_with?('wt.')
  end

  def self.drop_reserved(attrs)
    attrs.reject { |k, _| reserved?(k) }
  end

  # Drops wt.* and applies the hook; the hook returns the new value, or nil to drop.
  def self.redact(attrs, hook = nil)
    out = {}
    drop_reserved(attrs).each do |k, v|
      v = hook.call(k, v) if hook
      out[k] = v unless v.nil?
    end
    out
  end

  # Wraps an OTLP exporter: redacts on export and retries failed batches next time.
  class Exporter
    def initialize(inner, hook, buffer)
      @inner = inner
      @hook = hook
      @buffer = buffer
    end

    def export(span_datas, timeout: nil)
      span_datas.each do |s|
        s.attributes = Watchtower.redact(s.attributes || {}, @hook) if s.respond_to?(:attributes=)
      end
      pending = @buffer.drain
      result = OpenTelemetry::SDK::Trace::Export::SUCCESS
      (pending + [span_datas]).each do |batch|
        next if @inner.export(batch, timeout: timeout) == OpenTelemetry::SDK::Trace::Export::SUCCESS

        @buffer.push(batch)
        result = OpenTelemetry::SDK::Trace::Export::FAILURE
      end
      result
    end

    def force_flush(timeout: nil) = @inner.force_flush(timeout: timeout)
    def shutdown(timeout: nil) = @inner.shutdown(timeout: timeout)
  end

  # Configures the global OpenTelemetry SDK. Returns the Config.
  # instrument: true also enables the OTel Ruby instrumentations (Rack, Rails, Sidekiq, ...) when
  # the opentelemetry-instrumentation-all gem is installed.
  def self.init(config, instrument: true)
    require 'opentelemetry/sdk'
    require 'opentelemetry/exporter/otlp'
    use_all = instrument && begin
      require 'opentelemetry/instrumentation/all'
      true
    rescue LoadError
      false
    end
    @redactor = config.redactor
    inner = OpenTelemetry::Exporter::OTLP::Exporter.new(
      endpoint: "#{config.endpoint}/v1/traces", headers: config.headers
    )
    exporter = Exporter.new(inner, config.redactor, OfflineBuffer.new)
    OpenTelemetry::SDK.configure do |c|
      c.use_all if use_all
      c.resource = OpenTelemetry::SDK::Resources::Resource.create(config.resource_attributes)
      c.add_span_processor(OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(exporter))
    end
    config
  end

  def self.redactor = @redactor
end

%w[capture rack sidekiq log_bridge rails].each { |f| require_relative "watchtower/#{f}" }
