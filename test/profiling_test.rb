# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/watchtower'
require_relative '../lib/watchtower/profiling'

class ProfilingTest < Minitest::Test
  KEY = 'wtk_example_not_a_real_key' # fake

  def test_samples_other_threads_root_first
    q = Queue.new
    t = Thread.new { q.pop }
    sleep 0.05
    counts = Watchtower::Profiler.sample_once({})
    q << :done
    t.join
    refute_empty counts
    assert(counts.keys.all? { |k| !k.split(';').first.include?(';') })
    assert_equal "a;b 2\n", Watchtower::Profiler.body({ 'a;b' => 2 })
  end

  def test_with_span_labels_only_that_thread
    ready = Queue.new
    done = Queue.new
    t = Thread.new do
      Watchtower::Profiler.with_span(span_id: 'ab', trace_id: 'cd') do
        ready << true
        done.pop
      end
    end
    ready.pop
    counts = Watchtower::Profiler.sample_once({})
    done << true
    t.join
    assert(counts.keys.any? { |k| k.start_with?("span_id=ab,trace_id=cd\t") })
  end

  def test_with_span_stays_with_its_fiber
    ready = Queue.new
    done = Queue.new
    t = Thread.new do
      labeled = Fiber.new { Watchtower::Profiler.with_span(span_id: 'ef', trace_id: '01') { Fiber.yield } }
      labeled.resume # now suspended inside its span
      ready << true
      done.pop # the thread's root fiber runs here, outside the span
      labeled.resume
    end
    ready.pop
    counts = Watchtower::Profiler.sample_once({})
    done << true
    t.join
    refute_empty counts
    refute(counts.keys.any? { |k| k.start_with?('span_id=ef,') })
  end

  def test_url_and_key
    p = Watchtower::Profiler.new(key: KEY, endpoint: 'http://gw:4318/', service: 'api', tags: { env: 'prod' })
    q = URI.decode_www_form(p.url(10, 25).query).to_h
    assert_equal 'api.wall{env=prod}', q['name']
    assert_equal %w[10 25 folded], q.values_at('from', 'until', 'format')
    refute_includes p.inspect, KEY
    assert_raises(ArgumentError) { Watchtower::Profiler.new(key: nil) }
    dead = Watchtower::Profiler.new(key: KEY, endpoint: 'http://127.0.0.1:9')
    dead.upload({ 'a' => 1 }, 0, 1)
    assert_equal 1, dead.dropped
  end
end
