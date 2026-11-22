# frozen_string_literal: true

require 'minitest/autorun'
require 'opentelemetry/sdk'
require_relative '../lib/watchtower/probes'

PROBE_SPANS = OpenTelemetry::SDK::Trace::Export::InMemorySpanExporter.new

class ProbesTest < Minitest::Test
  # Probe target: a method with locals.
  class Shop
    def checkout(user, total)
      tax = total * 0.2
      tax + 1
    end

    def pay(amount)
      raise ArgumentError, 'negative' if amount.negative?

      plan = 'pro'
      plan.length + amount
    end
  end

  # A value whose methods must never run during a snapshot or a condition.
  class Trap
    def initialize
      @id = 7
    end

    def to_s = raise('to_s ran')
    def ==(_other) = raise('== ran')
  end

  def probes(defs, events)
    s = Watchtower::Probes::ProbeSet.new(endpoint: 'http://127.0.0.1:1', key: 'k', service: 's',
                                        emit: ->(n, a) { events << [n, a] }, now: -> { 1000.0 })
    s.set(defs)
    s
  end

  # Added at test time: another test file may configure the SDK after this one loads.
  def spans
    unless defined?(@@spans_on)
      proc = OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(PROBE_SPANS)
      if OpenTelemetry.tracer_provider.is_a?(OpenTelemetry::SDK::Trace::TracerProvider)
        OpenTelemetry.tracer_provider.add_span_processor(proc)
      else
        OpenTelemetry::SDK.configure { |c| c.add_span_processor(proc) }
      end
      @@spans_on = true
    end
    PROBE_SPANS.reset
    PROBE_SPANS
  end

  def test_span_probe_wraps_the_method_and_marks_errors
    mem = spans
    s = probes([{ 'id' => 'sp', 'kind' => 'span', 'location' => { 'function' => 'ProbesTest::Shop#pay' },
                  'condition' => 'amount != 1' },
                { 'id' => 'sd', 'kind' => 'span_decoration', 'location' => { 'function' => 'pay' },
                  'capture' => { 'tags' => [{ 'name' => 'pay.amount', 'value' => 'n={amount}' },
                                            { 'name' => 'wt.tenant', 'value' => 'x' }] } }], [])
    shop = Shop.new
    assert_equal 5, shop.pay(2)
    shop.pay(1) # condition false: no span
    assert_raises(ArgumentError) { shop.pay(-1) }
    s.set([])
    shop.pay(3) # removed: no span
    got = mem.finished_spans
    assert_equal ['probe pay', 'probe pay'], got.map(&:name)
    assert_equal 'sp', got[0].attributes['probe.id']
    assert_equal 'n=2', got[0].attributes['pay.amount']
    refute got[0].attributes.key?('wt.tenant')
    assert_equal OpenTelemetry::Trace::Status::ERROR, got[1].status.code
    assert(got[1].events.any? { |e| e.name == 'exception' })
    assert_empty Thread.current[:wt_probe_spans]
  end

  def test_line_span_decoration_tags_the_active_span
    mem = spans
    line = Shop.instance_method(:pay).source_location[1] + 4
    s = probes([{ 'id' => 'ld', 'kind' => 'span_decoration', 'condition' => "plan == 'pro'",
                  'location' => { 'file' => 'probes_test.rb', 'line' => line },
                  'capture' => { 'tags' => [{ 'name' => 'user.plan', 'value' => '{plan}' }] } }], [])
    OpenTelemetry.tracer_provider.tracer('t').in_span('outer') { Shop.new.pay(1) }
    s.set([])
    assert_equal 'pro', mem.finished_spans.last.attributes['user.plan']
  end

  def test_render_reads_plain_values_only
    v = { 'user' => Trap.new, 'n' => 3 }
    assert_equal 'id=7 n=3 u= x=', Watchtower::Probes.render('id={user.id} n={n} u={user} x={missing}', v)
  end

  def test_function_probe_snapshots_args_without_calling_user_code
    events = []
    s = probes([{ 'id' => 'p1', 'location' => { 'function' => 'ProbesTest::Shop#checkout' },
                  'condition' => 'total > 10', 'capture' => {}, 'max_rate_per_min' => 2 }], events)
    shop = Shop.new
    3.times { shop.checkout(Trap.new, 50) }
    shop.checkout(Trap.new, 5) # condition false
    s.set([])
    assert_equal 2, events.length, 'rate limit of 2 per minute'
    attrs = events[0][1]
    assert_equal 'p1', attrs['probe.id']
    assert_equal '50', attrs['code.snapshot.total']
    assert_equal '7', attrs['code.snapshot.user.id']
  end

  def test_line_probe_reads_locals_at_that_line
    events = []
    line = Shop.instance_method(:checkout).source_location[1] + 2
    s = probes([{ 'id' => 'p2', 'location' => { 'file' => 'probes_test.rb', 'line' => line } }], events)
    Shop.new.checkout(nil, 10)
    s.set([])
    assert_equal 1, events.length
    assert_equal '2.0', events[0][1]['code.snapshot.tax']
  end

  def test_condition_subset_refuses_calls_and_compares_only_plain_values
    assert_raises(ArgumentError) { Watchtower::Probes.compile('system("x")') }
    c = Watchtower::Probes.compile("user.id == 7 && name in ['a', 'b']")
    assert c.call({ 'user' => Trap.new, 'name' => 'a' })
    refute Watchtower::Probes.compile('user == 1').call({ 'user' => Trap.new })
  end

  def test_capture_bounds
    out = Watchtower::Probes.capture({ 'a' => { 'b' => { 'c' => { 'd' => 1 } } }, 'big' => 'x' * 5000 }, 2, 2000)
    assert_equal '[depth limit]', out['a.b.c']
    assert_equal 1024, out['big'].length
  end
end
