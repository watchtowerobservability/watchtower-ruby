# frozen_string_literal: true

require 'net/http'
require 'uri'

module Watchtower
  # Continuous wall-clock profiler in plain Ruby: a thread samples every other thread's
  # backtrace `hz` times a second, folds the stacks and posts them every `period` seconds to the
  # gateway's Pyroscope-compatible `/ingest` as `<service>.wall` (format `folded`). Uploads are
  # best effort: a failure is counted and dropped. `Profiler.with_span` labels the current
  # fiber's samples with a span, so a trace links to its exact profile. The label is fiber-local,
  # so with fiber schedulers (the async gem) other fibers on the thread stay unlabeled.
  class Profiler
    MAX_DEPTH = 128
    attr_reader :uploaded, :dropped

    def initialize(key: ENV.fetch('WT_INGEST_KEY', nil), endpoint: ENV.fetch('WT_OTLP_ENDPOINT', nil),
                   service: ENV.fetch('WT_SERVICE', 'app'), tags: {}, hz: 100, period: 15.0)
      raise ArgumentError, 'key is required' if key.nil? || key.empty?

      @key = key
      @endpoint = (endpoint || DEFAULT_ENDPOINT).sub(%r{/+\z}, '')
      @service = service
      @tags = { 'env' => ENV.fetch('WT_ENVIRONMENT', nil), 'version' => ENV.fetch('WT_RELEASE', nil) }
              .merge(tags.transform_keys(&:to_s))
      @hz = hz.to_i.clamp(1, 250)
      @period = [period.to_f, 1.0].max
      @uploaded = 0
      @dropped = 0
    end

    def inspect
      "#<Watchtower::Profiler service=#{@service}>"
    end

    def self.fold(locations)
      locations.first(MAX_DEPTH).reverse.map do |l|
        "#{l.label} (#{File.basename(l.path.to_s)}:#{l.lineno})".tr(';', ':')
      end.join(';')
    end

    # Labels this fiber's samples with a span; the default is the current OpenTelemetry span.
    def self.with_span(span_id: nil, trace_id: nil)
      if span_id.nil? && defined?(OpenTelemetry::Trace)
        ctx = OpenTelemetry::Trace.current_span.context
        span_id = ctx.hex_span_id if ctx.valid?
        trace_id = ctx.hex_trace_id if ctx.valid?
      end
      return yield if span_id.nil?

      # Thread#[] is fiber-local; read from the sampler it gives the thread's running fiber's.
      before = Thread.current[:wt_span]
      Thread.current[:wt_span] = "span_id=#{span_id},trace_id=#{trace_id}\t"
      begin
        yield
      ensure
        Thread.current[:wt_span] = before
      end
    end

    def self.sample_once(counts, skip = Thread.current)
      Thread.list.each do |t|
        next if t.equal?(skip)

        locs = t.backtrace_locations
        next if locs.nil? || locs.empty?

        key = "#{t[:wt_span]}#{fold(locs)}"
        counts[key] = counts.fetch(key, 0) + 1
      end
      counts
    end

    def self.body(counts)
      counts.map { |k, n| "#{k} #{n}\n" }.join
    end

    def url(from, till)
      labels = @tags.reject { |_, v| v.nil? || v.to_s.empty? }.sort.map { |k, v| "#{k}=#{v}" }.join(',')
      q = URI.encode_www_form(name: "#{@service}.wall{#{labels}}", from: from.to_i, until: till.to_i,
                              format: 'folded', sampleRate: @hz, spyName: 'watchtower-ruby', units: 'samples')
      URI("#{@endpoint}/ingest?#{q}")
    end

    def start
      @thread ||= Thread.new do
        Thread.current.name = 'watchtower-profiler'
        loop_once until @stop
      end
      self
    end

    def stop
      @stop = true
      @thread&.join(@period + 5)
      @thread = nil
    end

    def upload(counts, from, till)
      u = url(from, till)
      req = Net::HTTP::Post.new(u, 'Authorization' => "Bearer #{@key}", 'Content-Type' => 'text/plain')
      req.body = self.class.body(counts)
      Net::HTTP.start(u.host, u.port, use_ssl: u.scheme == 'https', open_timeout: 5, read_timeout: 10) do |h|
        h.request(req).is_a?(Net::HTTPSuccess) ? @uploaded += 1 : @dropped += 1
      end
    rescue StandardError
      @dropped += 1
    end

    private

    def loop_once
      counts = {}
      from = Time.now
      while !@stop && Time.now - from < @period
        self.class.sample_once(counts)
        sleep(1.0 / @hz)
      end
      upload(counts, from, Time.now) unless counts.empty?
    end
  end
end
