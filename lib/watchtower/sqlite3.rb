# frozen_string_literal: true

require_relative 'sqlnorm'

module Watchtower
  # sqlite3 gem: a client span per statement run through SQLite3::Database (execute, execute2,
  # execute_batch, execute_batch2, query, get_first_row, get_first_value), with db.query.hash and
  # db.query.summary; never the raw statement or bind values.
  #   require 'sqlite3'; require 'watchtower/sqlite3'; Watchtower::SQLite3.instrument
  # with_text: true adds db.query.text with every literal replaced by ?.
  module SQLite3
    METHODS = %i[execute execute2 execute_batch execute_batch2 query get_first_row get_first_value].freeze

    class << self
      attr_accessor :with_text

      def instrument(with_text: false)
        self.with_text = with_text
        ::SQLite3::Database.prepend(Patch) unless ::SQLite3::Database <= Patch
      end

      # Wrap the block in a span for sql; nested calls (get_first_row -> execute) get one span.
      def trace(db, sql)
        return yield if Thread.current[:watchtower_sqlite3]

        attrs = SqlNorm.attributes(sql.to_s, system: 'sqlite', with_text: with_text == true)
        attrs['db.system.name'] = 'sqlite'
        ns = namespace(db)
        attrs['db.namespace'] = ns if ns
        name = attrs['db.query.summary'] || 'sqlite'
        OpenTelemetry.tracer_provider.tracer('watchtower.sqlite3').in_span(name, attributes: attrs, kind: :client) do
          Thread.current[:watchtower_sqlite3] = true
          yield
        ensure
          Thread.current[:watchtower_sqlite3] = nil
        end
      end

      def namespace(db)
        f = db.respond_to?(:filename) ? db.filename('main') : nil
        f.nil? || f.empty? ? ':memory:' : f
      rescue StandardError
        nil
      end
    end

    # Prepended into SQLite3::Database.
    module Patch
      METHODS.each do |m|
        define_method(m) do |sql, *args, **kw, &blk|
          Watchtower::SQLite3.trace(self, sql) { super(sql, *args, **kw, &blk) }
        end
      end
    end
  end
end
