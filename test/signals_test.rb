# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require 'tmpdir'
require 'zlib'
require 'opentelemetry/sdk'
require_relative '../lib/watchtower'

# Logs and metrics reach a fake OTLP endpoint; log records carry the active trace and span ids.
# Signals.start_* are called directly so the global trace setup of the other tests stays as it is.
class SignalsTest < Minitest::Test
  Req = Struct.new(:path, :auth, :body)

  # One request at a time; records path, auth header and the (gunzipped) body, answers 200.
  def collector(got)
    srv = TCPServer.new('127.0.0.1', 0)
    th = Thread.new do
      loop do
        c = srv.accept
        path = c.gets.to_s.split[1]
        h = {}
        while (line = c.gets) && line != "\r\n"
          k, v = line.split(':', 2)
          h[k.downcase] = v.to_s.strip
        end
        body = c.read(h['content-length'].to_i)
        body = Zlib.gunzip(body) if h['content-encoding'] == 'gzip'
        got << Req.new(path, h['authorization'], body)
        c.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        c.close
      end
    end
    [srv, th]
  end

  def resource = OpenTelemetry::SDK::Resources::Resource.create('service.name' => 'svc')

  def test_logger_records_and_metrics_reach_the_endpoint
    got = Queue.new
    srv, th = collector(got)
    cfg = Watchtower::Config.new(service: 'svc', endpoint: "http://127.0.0.1:#{srv.addr[1]}", key: 'k')
    lp = Watchtower::Signals.start_logs(cfg, resource)
    mp = Watchtower::Signals.start_metrics(cfg, resource)
    Watchtower.instance_variable_set(:@logs, true)
    log = Watchtower::LogBridge.new(Logger.new(File::NULL))
    tp = OpenTelemetry::SDK::Trace::TracerProvider.new
    ctx = nil
    tp.tracer('t').in_span('op') do |span|
      ctx = span.context
      log.warn('hello from logger')
    end
    mp.meter('t').create_counter('jobs.done').add(3)
    lp.force_flush
    mp.force_flush
    reqs = []
    reqs << got.pop until got.empty?
    logs = reqs.select { |r| r.path == '/v1/logs' }.map(&:body).join
    assert_includes logs, 'hello from logger'
    assert_includes logs, ctx.trace_id, 'log record carries the trace id'
    assert_includes logs, ctx.span_id, 'log record carries the span id'
    assert_includes reqs.select { |r| r.path == '/v1/metrics' }.map(&:body).join, 'jobs.done'
    assert(reqs.all? { |r| r.auth == 'Bearer k' })
    assert_equal 'delta', ENV.fetch('OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE')
  ensure
    Watchtower.instance_variable_set(:@logs, nil)
    lp&.shutdown
    mp&.shutdown
    th&.kill
    srv&.close
  end

  class Failing
    attr_accessor :down

    def export(_batch, timeout: nil) = down ? :failed : :ok
    def force_flush(timeout: nil) = :ok
    def shutdown(timeout: nil) = :ok

    private

    def encode(batch) = "pb:#{batch.join(',')}"
  end

  def test_failed_batches_spool_through_the_exporter_encoder_and_replay
    Dir.mktmpdir do |dir|
      got = Queue.new
      srv, th = collector(got)
      cfg = Watchtower::Config.new(service: 'svc', endpoint: "http://127.0.0.1:#{srv.addr[1]}", key: 'k', spool_dir: dir)
      inner = Failing.new
      inner.down = true
      exp = Watchtower::Signals.spooled(inner, cfg, 'metrics', :ok)
      exp.export(%w[a b])
      assert_equal 1, Dir.glob(File.join(dir, 'metrics', '*.pb')).size
      inner.down = false
      exp.export(%w[c])
      r = got.pop
      assert_equal ['/v1/metrics', 'Bearer k', 'pb:a,b'], [r.path, r.auth, r.body]
      assert_empty Dir.glob(File.join(dir, 'metrics', '*.pb'))
    ensure
      th&.kill
      srv&.close
    end
  end

  def test_switches
    refute Watchtower::Signals.on?(false, 'WATCHTOWER_LOGS', 'OTEL_LOGS_EXPORTER')
    ENV['WATCHTOWER_METRICS'] = 'off'
    refute Watchtower::Signals.on?(nil, 'WATCHTOWER_METRICS', 'OTEL_METRICS_EXPORTER')
  ensure
    ENV.delete('WATCHTOWER_METRICS')
  end
end

class LogBridgeCallerTest < Minitest::Test
  def test_caller_attrs_skip_the_bridge_and_stdlib_logger
    attrs = Watchtower::LogBridge.caller_attrs(caller_locations(0, 5))
    assert_equal __FILE__, attrs['code.filepath']
    assert_kind_of Integer, attrs['code.lineno']
  end
end
