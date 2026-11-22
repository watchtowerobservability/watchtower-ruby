# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'opentelemetry/sdk'
require_relative '../lib/watchtower/sqlnorm'

class SqlNormTest < Minitest::Test
  VECTORS = File.expand_path('../../../testdata/sql_normalize_vectors.json', __dir__)

  def test_shared_vectors
    skip 'shared vectors not in this checkout' unless File.exist?(VECTORS)
    vectors = JSON.parse(File.read(VECTORS))['vectors']
    refute_empty vectors
    vectors.each do |v|
      n = Watchtower::SqlNorm.normalize(v['input'], v['pg'])
      assert_equal v['normalized'], n, v['name']
      assert_equal v['hash'], Watchtower::SqlNorm.query_hash(v['normalized']), v['name']
    end
  end

  def test_summary
    assert_equal %w[SELECT users], Watchtower::SqlNorm.summary('SELECT * FROM users WHERE id = ?')
    assert_equal %w[UPDATE public.jobs], Watchtower::SqlNorm.summary('update "public"."jobs" set a = ?')
    assert_equal %w[DELETE t], Watchtower::SqlNorm.summary('WITH x AS (SELECT ?) DELETE FROM t')
  end
end

class SQLite3IntegrationTest < Minitest::Test
  def setup
    begin
      require 'sqlite3'
    rescue LoadError
      skip 'sqlite3 gem not installed'
    end
    require_relative '../lib/watchtower/sqlite3'
    @exporter = OpenTelemetry::SDK::Trace::Export::InMemorySpanExporter.new
    # Add to the shared provider: re-configuring the SDK would detach the other test files' exporters.
    proc = OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(@exporter)
    if OpenTelemetry.tracer_provider.is_a?(OpenTelemetry::SDK::Trace::TracerProvider)
      OpenTelemetry.tracer_provider.add_span_processor(proc)
    else
      OpenTelemetry::SDK.configure { |c| c.add_span_processor(proc) }
    end
    Watchtower::SQLite3.instrument
  end

  def test_spans_carry_hash_not_values
    db = ::SQLite3::Database.new(':memory:')
    db.execute('create table users (id integer, email text)')
    db.execute("insert into users values (1, 'alice@example.com')")
    assert_equal 1, db.get_first_value('select count(*) from users where email = ?', ['alice@example.com'])
    spans = @exporter.finished_spans
    assert_equal ['CREATE users', 'INSERT users', 'SELECT users'], spans.map(&:name)
    a = spans[1].attributes
    assert_equal 'sqlite', a['db.system.name']
    assert_match(/\A\d+\z/, a['db.query.hash'])
    refute_includes spans.map { |s| s.attributes.to_s }.join, 'alice'
    assert_raises(::SQLite3::SQLException) { db.execute('select * from missing') }
    assert_equal OpenTelemetry::Trace::Status::ERROR, @exporter.finished_spans.last.status.code
  end
end
