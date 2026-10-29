# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/watchtower'

class InitTest < Minitest::Test
  KEY = 'wtk_example_not_a_real_key' # fake

  def test_exports_with_key_header
    c = Watchtower::Config.new(service: 'svc', key: KEY)
    assert_equal({ 'authorization' => "Bearer #{KEY}" }, c.headers)
    assert_equal 'http://localhost:4318', c.endpoint
    refute_includes c.inspect, KEY
  end

  def test_wt_attributes_dropped
    c = Watchtower::Config.new(service: 'svc', endpoint: 'https://x.example/',
                               resource: { 'wt.project_id' => 'p', 'env' => 'prod' })
    assert_equal({ 'service.name' => 'svc', 'env' => 'prod' }, c.resource_attributes)
    assert_equal 'https://x.example', c.endpoint
    assert_equal({ 'a' => 'b' }, Watchtower.redact({ 'wt.tenant' => 't', 'a' => 'b' }))
  end

  def test_redaction_hook_masks_and_drops
    hook = ->(k, v) { k == 'password' ? nil : (k == 'email' ? '[redacted]' : v) }
    out = Watchtower.redact({ 'password' => 'x', 'email' => 'a@b.c', 'n' => 1 }, hook)
    assert_equal({ 'email' => '[redacted]', 'n' => 1 }, out)
  end

  def test_buffer_drops_oldest
    b = Watchtower::OfflineBuffer.new(2)
    [1, 2, 3].each { |i| b.push(i) }
    assert_equal [2, 3], b.drain
  end
end
