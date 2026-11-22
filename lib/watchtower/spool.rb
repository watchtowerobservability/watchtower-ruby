# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

module Watchtower
  # File spool: a failed batch is written to `dir` as an OTLP request and POSTed again, oldest
  # first, before the next export, so it survives a process restart. At most `max_files` batches
  # are kept (drop-oldest). Delivery stays at-least-once. Spans are written as OTLP/JSON by default;
  # logs and metrics pass `encode:` (the official exporter's protobuf encoding) and its content type.
  class FileSpool
    KINDS = { internal: 1, server: 2, client: 3, producer: 4, consumer: 5 }.freeze

    def initialize(dir, url:, headers: {}, max_files: 500, encode: nil, content_type: 'application/json')
      @dir = dir
      @encode = encode || ->(batch) { JSON.generate(FileSpool.otlp(batch)) }
      @content_type = content_type
      @ext = content_type == 'application/json' ? 'json' : 'pb'
      @url = URI(url)
      @headers = headers
      @max = [max_files, 1].max
      @seq = 0
      @lock = Mutex.new
      FileUtils.mkdir_p(dir)
    end

    def files
      Dir.glob(File.join(@dir, "*.#{@ext}")).sort
    end

    def size = files.size

    # Spooled batches are replayed over HTTP, not handed back to the exporter.
    def drain = []

    def push(batch)
      @lock.synchronize do
        have = files
        have.first(have.size - @max + 1).each { |f| File.delete(f) } if have.size >= @max
        @seq += 1
        name = format('%<t>013d-%<s>06d-%<u>s.%<e>s', t: (Time.now.to_f * 1000).to_i, s: @seq % 1_000_000,
                                                       u: SecureRandom.hex(4), e: @ext)
        tmp = File.join(@dir, "#{name}.tmp")
        File.binwrite(tmp, @encode.call(batch))
        File.rename(tmp, File.join(@dir, name))
      end
    rescue SystemCallError
      nil # disk full or not writable: the batch is lost, as without a spool
    end

    # Sends spooled batches in order; stops at the first failure so order is kept.
    def replay
      files.each do |f|
        req = Net::HTTP::Post.new(@url, { 'content-type' => @content_type }.merge(@headers))
        req.body = File.binread(f)
        res = Net::HTTP.start(@url.host, @url.port, use_ssl: @url.scheme == 'https',
                                                    open_timeout: 5, read_timeout: 10) { |h| h.request(req) }
        return unless res.is_a?(Net::HTTPSuccess)

        File.delete(f)
      end
    rescue StandardError
      nil # still offline
    end

    def self.value(v)
      case v
      when String then { stringValue: v }
      when Integer then { intValue: v.to_s }
      when Float then { doubleValue: v }
      when true, false then { boolValue: v }
      when Array then { arrayValue: { values: v.map { |x| value(x) } } }
      else { stringValue: v.to_s }
      end
    end

    def self.attrs(h)
      (h || {}).map { |k, v| { key: k.to_s, value: value(v) } }
    end

    def self.hex(bin) = bin.to_s.unpack1('H*')

    def self.status(s)
      code = s&.code
      { code: if code == OpenTelemetry::Trace::Status::ERROR then 2
              elsif code == OpenTelemetry::Trace::Status::OK then 1
              else 0
              end, message: s&.description.to_s }
    end

    def self.span(s)
      parent = s.parent_span_id
      {
        traceId: hex(s.trace_id), spanId: hex(s.span_id),
        parentSpanId: parent.nil? || parent == OpenTelemetry::Trace::INVALID_SPAN_ID ? '' : hex(parent),
        name: s.name, kind: KINDS.fetch(s.kind, 1),
        startTimeUnixNano: s.start_timestamp.to_s, endTimeUnixNano: s.end_timestamp.to_s,
        attributes: attrs(s.attributes),
        events: (s.events || []).map { |e| { timeUnixNano: e.timestamp.to_s, name: e.name, attributes: attrs(e.attributes) } },
        status: status(s.status)
      }
    end

    # One ExportTraceServiceRequest in OTLP/JSON, grouped by resource and scope.
    def self.otlp(batch)
      by_res = batch.group_by(&:resource)
      { resourceSpans: by_res.map do |res, spans|
        {
          resource: { attributes: attrs(res&.attribute_enumerator&.to_h) },
          scopeSpans: spans.group_by(&:instrumentation_scope).map do |sc, ss|
            { scope: { name: sc&.name.to_s, version: sc&.version.to_s }, spans: ss.map { |x| span(x) } }
          end
        }
      end }
    end
  end
end
