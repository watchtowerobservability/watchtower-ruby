# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/watchtower/appsec'

class AppsecTest < Minitest::Test
  RULES = {
    'mode' => 'block',
    'rules' => [
      { 'id' => 'sqli', 'category' => 'injection', 'pattern' => "union\\s+select|' or 1=1", 'fields' => %w[path query] },
      { 'id' => 'bad', 'category' => 'x', 'pattern' => '(', 'fields' => ['path'] }
    ],
    'denylist' => { 'ip' => [{ 'value' => '203.0.113.9', 'expires_at' => 4_102_444_800 }],
                    'user' => [{ 'value' => 'mallory' }] }
  }.freeze

  def setup
    Watchtower::Appsec.set_ruleset(RULES)
  end

  def env(query, extra = {})
    { 'PATH_INFO' => '/items', 'REQUEST_URI' => "/items?#{query}", 'QUERY_STRING' => query,
      'REMOTE_ADDR' => '10.0.0.1' }.merge(extra)
  end

  def test_a_percent_encoded_injection_is_blocked_and_clean_requests_pass
    d = Watchtower::Appsec.inspect_request(Watchtower::Appsec.from_env(env('q=1%27%20OR%201%3D1')))
    assert_equal %w[block sqli], [d[:action], d[:rule_id]]
    assert_equal 'allow', Watchtower::Appsec.inspect_request(Watchtower::Appsec.from_env(env('q=shoes')))[:action]
  end

  def test_monitor_mode_flags_without_blocking_and_denylist_always_blocks
    Watchtower::Appsec.set_ruleset(RULES.merge('mode' => 'monitor'))
    d = Watchtower::Appsec.inspect_request(Watchtower::Appsec.from_env(env('q=1+union+select+1')))
    assert_equal 'monitor', d[:action]
    d = Watchtower::Appsec.inspect_request(Watchtower::Appsec.from_env(env('q=ok', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9')))
    assert_equal ['block', 'denylist'], [d[:action], d[:rule_id]]
    assert Watchtower::Appsec.user_blocked?('mallory')
  end

  def test_middleware_answers_403_problem_json_and_skips_the_app
    called = false
    app = Watchtower::Appsec::Middleware.new(->(_e) { called = true; [200, {}, ['ok']] })
    status, headers, body = app.call(env('q=1%20union%20select%201'))
    assert_equal 403, status
    assert_equal 'application/problem+json', headers['content-type']
    assert_includes body.first, 'Forbidden'
    refute called
    assert_equal 200, app.call(env('q=ok')).first
  end

  def test_nothing_happens_until_a_ruleset_is_set
    Watchtower::Appsec.set_ruleset(nil)
    refute Watchtower::Appsec.active?
  end
end
