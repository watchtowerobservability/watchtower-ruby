# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'socket'
require 'tmpdir'
require 'opentelemetry/sdk'
require_relative '../lib/watchtower'

class SpoolTest < Minitest::Test
  def span_batch(name)
    mem = OpenTelemetry::SDK::Trace::Export::InMemorySpanExporter.new
    tp = OpenTelemetry::SDK::Trace::TracerProvider.new
    tp.add_span_processor(OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(mem))
    tp.tracer('t').in_span(name, attributes: { 'http.status_code' => 500, 'ok' => false }, kind: :server) do |s|
      s.status = OpenTelemetry::Trace::Status.error('boom')
    end
    mem.finished_spans
  end

  # A one-request-at-a-time HTTP server that records bodies and answers 200.
  def collector(bodies)
    srv = TCPServer.new('127.0.0.1', 0)
    th = Thread.new do
      loop do
        c = srv.accept
        len = 0
        while (line = c.gets) && line != "\r\n"
          len = line.split(':', 2)[1].to_i if line.downcase.start_with?('content-length')
        end
        bodies << c.read(len)
        c.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        c.close
      end
    end
    [srv, th]
  end

  def test_otlp_json_shape
    req = Watchtower::FileSpool.otlp(span_batch('GET /cart'))
    span = req[:resourceSpans][0][:scopeSpans][0][:spans][0]
    assert_equal 'GET /cart', span[:name]
    assert_equal 2, span[:kind]
    assert_equal 32, span[:traceId].size
    assert_equal({ code: 2, message: 'boom' }, span[:status])
    assert_includes span[:attributes], { key: 'http.status_code', value: { intValue: '500' } }
    assert_includes span[:attributes], { key: 'ok', value: { boolValue: false } }
  end

  def test_spools_to_disk_drops_oldest_and_replays_in_order
    Dir.mktmpdir do |dir|
      bodies = []
      srv, th = collector(bodies)
      port = srv.addr[1]
      spool = Watchtower::FileSpool.new(dir, url: "http://127.0.0.1:#{port}/v1/traces", headers: { 'authorization' => 'Bearer k' },
                                             max_files: 2)
      %w[a b c].each { |n| spool.push(span_batch(n)) }
      assert_equal 2, spool.size
      assert_empty spool.drain
      spool.replay
      assert_equal 0, spool.size
      names = bodies.map { |b| JSON.parse(b)['resourceSpans'][0]['scopeSpans'][0]['spans'][0]['name'] }
      assert_equal %w[b c], names
    ensure
      th&.kill
      srv&.close
    end
  end

  def test_replay_keeps_files_while_offline
    Dir.mktmpdir do |dir|
      spool = Watchtower::FileSpool.new(dir, url: 'http://127.0.0.1:9/v1/traces')
      spool.push(span_batch('x'))
      spool.replay
      assert_equal 1, spool.size
    end
  end
end
