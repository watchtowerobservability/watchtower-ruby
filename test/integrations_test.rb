# frozen_string_literal: true

require 'minitest/autorun'
require 'stringio'
require 'opentelemetry/sdk'
require_relative '../lib/watchtower'

EXPORTER = OpenTelemetry::SDK::Trace::Export::InMemorySpanExporter.new
OpenTelemetry::SDK.configure do |c|
  c.add_span_processor(OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(EXPORTER))
end

class IntegrationsTest < Minitest::Test
  def setup
    EXPORTER.reset
  end

  def exception_event(span)
    span.events.find { |e| e.name == 'exception' }
  end

  def test_capture_exception_makes_span_with_ids_and_drops_wt_attrs
    ids = Watchtower.capture_exception(RuntimeError.new('boom'), 'wt.tenant' => 't', 'a' => 'b')
    span = EXPORTER.finished_spans.last
    assert_equal span.hex_trace_id, ids[:trace_id]
    assert_equal 'boom', exception_event(span).attributes['exception.message']
    assert_equal 'b', exception_event(span).attributes['a']
    refute exception_event(span).attributes.key?('wt.tenant')
  end

  def test_capture_dedupes
    e = RuntimeError.new('x')
    assert Watchtower.capture_exception(e)
    assert_nil Watchtower.capture_exception(e)
    assert_equal 1, EXPORTER.finished_spans.size
  end

  def test_rack_captures_and_reraises
    app = ->(_env) { raise ArgumentError, 'bad' }
    assert_raises(ArgumentError) { Watchtower::RackMiddleware.new(app).call('PATH_INFO' => '/x') }
    assert_equal '/x', exception_event(EXPORTER.finished_spans.last).attributes['http.route']
  end

  def test_rack_captures_rescued_env_exception
    app = ->(_env) { [500, {}, []] }
    env = { 'PATH_INFO' => '/y', 'action_dispatch.exception' => StandardError.new('rescued') }
    Watchtower::RackMiddleware.new(app).call(env)
    assert_equal 1, EXPORTER.finished_spans.size
  end

  def test_sidekiq_captures_job_attributes
    mw = Watchtower::SidekiqMiddleware.new
    assert_raises(IOError) { mw.call(Object.new, { 'jid' => 'j1' }, 'default') { raise IOError, 'x' } }
    attrs = exception_event(EXPORTER.finished_spans.last).attributes
    assert_equal 'j1', attrs['sidekiq.job.id']
    assert_equal 'default', attrs['sidekiq.queue']
  end

  def test_rails_error_subscriber
    Watchtower::RailsIntegration::ErrorSubscriber.new.report(
      RuntimeError.new('r'), handled: true, severity: :warning, context: { user: 1 }, source: 'application'
    )
    attrs = exception_event(EXPORTER.finished_spans.last).attributes
    assert_equal 'warning', attrs['error.severity']
    assert_equal '1', attrs['rails.context.user']
  end

  def test_notifications_capture_exception_object
    bus = Object.new
    handlers = {}
    bus.define_singleton_method(:subscribe) { |ev, &blk| handlers[ev] = blk }
    Watchtower::RailsIntegration.subscribe_notifications(bus)
    handlers['perform.active_job'].call('perform.active_job', 0, 0, 'id', { exception_object: RuntimeError.new('job') })
    assert_equal 'active_job', exception_event(EXPORTER.finished_spans.last).attributes['error.source']
  end

  def test_log_bridge_adds_span_event_and_forwards
    io = StringIO.new
    log = Watchtower::LogBridge.new(Logger.new(io))
    OpenTelemetry.tracer_provider.tracer('t').in_span('s') { log.error('hello') }
    assert_includes io.string, 'hello'
    ev = EXPORTER.finished_spans.last.events.find { |e| e.name == 'log' }
    assert_equal 'ERROR', ev.attributes['log.severity']
  end

  def test_config_from_env
    ENV['WT_ENDPOINT'] = 'http://old:1'
    ENV['WT_ENVIRONMENT'] = 'prod'
    ENV['WT_RELEASE'] = '1.2.3'
    ENV['WT_SERVICE'] = 'svc'
    c = Watchtower::Config.from_env
    assert_equal 'http://old:1', c.endpoint
    ENV['WT_OTLP_ENDPOINT'] = 'http://new:2'
    assert_equal 'http://new:2', Watchtower::Config.from_env.endpoint
    assert_equal({ 'service.name' => 'svc', 'deployment.environment' => 'prod', 'service.version' => '1.2.3' },
                 c.resource_attributes)
  ensure
    %w[WT_ENDPOINT WT_OTLP_ENDPOINT WT_ENVIRONMENT WT_RELEASE WT_SERVICE].each { |k| ENV.delete(k) }
  end
end

class PayloadTest < Minitest::Test
  def setup
    EXPORTER.reset
  end

  def teardown
    Watchtower::Payload.rules = []
  end

  def test_rack_records_capped_redacted_bodies_per_route
    Watchtower::Payload.rules = [{ 'route' => '/api/*', 'body_bytes' => 40 }]
    app = ->(_env) { [200, { 'content-type' => 'image/png' }, ['png']] }
    body = '{"user":"a@b.io","password":"hunter2","card":"4111 1111 1111 1111"}'
    env = { 'PATH_INFO' => '/api/login', 'CONTENT_TYPE' => 'application/json', 'rack.input' => StringIO.new(body) }
    OpenTelemetry.tracer_provider.tracer('t').in_span('req') { Watchtower::RackMiddleware.new(app).call(env) }
    got = EXPORTER.finished_spans.last.attributes
    assert got['http.request.body'].bytesize <= 40
    refute_includes got['http.request.body'], 'hunter2'
    refute_includes got['http.request.body'], 'a@b.io'
    refute got.key?('http.response.body')
    assert_equal body, env['rack.input'].read # rewound for the app
    assert_equal '4111 1111 1111 1112', Watchtower::Payload.redact('4111 1111 1111 1112')
  end

  def test_graphql_operation_and_document
    Watchtower::Payload.rules = [{ 'graphql_query' => true }]
    span = OpenTelemetry.tracer_provider.tracer('t').start_span('gql')
    q = JSON.generate('query' => "# c\nmutation AddUser { add(email: \"x@y.io\") { id } }")
    Watchtower::Payload.record(span, '/graphql', 'application/json', q, nil, nil)
    span.finish
    got = EXPORTER.finished_spans.last.attributes
    assert_equal 'mutation', got['graphql.operation.type']
    assert_equal 'AddUser', got['graphql.operation.name']
    refute_includes got['graphql.document'], 'x@y.io'
    assert_nil Watchtower::Payload.graphql_op('shoes')
  end
end
