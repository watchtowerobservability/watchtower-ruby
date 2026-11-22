# frozen_string_literal: true

require 'digest/xxhash'

module Watchtower
  # Ruby port of services/worker/src/sqlnorm.rs: literal-free statement text plus its XXH3-64 hash
  # as a decimal string, so spans join agent DBM and the worker's wt.db.query_hash.
  # Spec: docs/product/instrumentation/sql-normalization.md; contract: testdata/sql_normalize_vectors.json.
  module SqlNorm
    MAX_LEN = 8192
    MAX_DOLLAR_TAG = 32
    PG_SYSTEMS = %w[postgresql cockroachdb redshift].freeze
    ALNUM = /\A[\p{Alphabetic}\p{N}]\z/
    SPACE = /\A\p{White_Space}\z/

    module_function

    def pg?(system) = PG_SYSTEMS.include?(system.to_s)
    def alnum?(c) = ALNUM.match?(c)
    def word?(c) = c == '_' || c == '$' || alnum?(c)
    def digit?(c) = !c.nil? && c >= '0' && c <= '9' && c.length == 1

    def cap(s)
      s = s.to_s.dup.force_encoding(Encoding::UTF_8)
      s.bytesize <= MAX_LEN ? s.scrub('') : s.byteslice(0, MAX_LEN).scrub('')
    end

    def dollar_quoted(cs, i)
      k = (cs[i + 1, MAX_DOLLAR_TAG + 1] || []).index('$')
      return nil if k.nil?

      tag = cs[i, k + 2]
      return nil unless tag[1..k].all? { |c| alnum?(c) || c == '_' } && !digit?(tag[1])

      j = (i + tag.size...cs.size).find { |x| cs[x, tag.size] == tag }
      j.nil? ? cs.size : j + tag.size
    end

    def token(cs, i, pg, out)
      c = cs[i]
      n = cs.size
      if c == "'"
        i += 1
        while i < n
          if cs[i] == "'"
            break unless cs[i + 1] == "'"

            i += 1
          end
          i += 1
        end
        out << '?'
        return i < n && cs[i - 1] == '\\' ? n : i + 1 # ambiguous MySQL escape: mask the rest
      end
      if ['"', '`'].include?(c)
        close = ((i + 1)...n).find { |j| cs[j] == c } || n
        body = cs[(i + 1)...close]
        ident = c == '"' && pg && close < n && body.size.between?(1, 64) &&
                body.all? { |b| alnum?(b) || b == '_' || b == '$' }
        out << (ident ? cs[i..close].join : '?')
        return close + 1
      end
      if c == '$'
        if digit?(cs[i + 1])
          i += 1
          i += 1 while i < n && digit?(cs[i])
          out << '?'
          return i
        end
        e = dollar_quoted(cs, i)
        if e
          out << '?'
          return e
        end
      end
      if digit?(c)
        i += 1 while i < n && (word?(cs[i]) || cs[i] == '.')
        out << '?'
      elsif word?(c)
        while i < n && word?(cs[i])
          out << cs[i]
          i += 1
        end
      else
        out << c
        i += 1
      end
      i
    end

    def normalize(stmt, pg = false)
      cs = cap(stmt).chars
      n = cs.size
      out = +''
      space = false
      i = 0
      while i < n
        c = cs[i]
        nxt = cs[i + 1]
        if SPACE.match?(c)
          space = true
          i += 1
        elsif c == '/' && nxt == '*'
          depth = 1
          i += 2
          while i < n && depth.positive?
            if cs[i] == '/' && cs[i + 1] == '*'
              depth += 1
              i += 2
            elsif cs[i] == '*' && cs[i + 1] == '/'
              depth -= 1
              i += 2
            else
              i += 1
            end
          end
          space = true
        elsif (c == '-' && nxt == '-') || (c == '#' && !pg)
          i += 1 while i < n && cs[i] != "\n"
          space = true
        else
          out << ' ' if space && !out.empty?
          space = false
          i = token(cs, i, pg, out)
        end
      end
      collapse_in(out)
    end

    def byte_word?(b)
      @byte_word ||= Array.new(256) { |x| word?(x.chr(Encoding::ISO_8859_1).encode(Encoding::UTF_8)) }
      @byte_word[b]
    end

    def in_list(b, i)
      skip = ->(k) { k += 1 while b[k] == 0x20; k }
      i = skip.call(i)
      open = i
      return nil unless b[i] == 0x28 # (

      i += 1
      loop do
        i = skip.call(i)
        return nil unless b[i] == 0x3F # ?

        i = skip.call(i + 1)
        case b[i]
        when 0x2C then i += 1 # ,
        when 0x29 then return [open, i + 1] # )
        else return nil
        end
      end
    end

    # `in (?, ?)` -> `in (?+)` on the UTF-8 bytes (word boundary: previous byte read as Latin-1).
    def collapse_in(s)
      b = s.bytes
      out = []
      i = 0
      while i < b.size
        at_word = i.zero? || !byte_word?(b[i - 1])
        if at_word && b.size - i >= 2 && (b[i] | 0x20) == 0x69 && (b[i + 1] | 0x20) == 0x6E
          m = in_list(b, i + 2)
          if m
            out.concat(b[i...m[0]], '(?+)'.bytes)
            i = m[1]
            next
          end
        end
        out << b[i]
        i += 1
      end
      out.pack('C*').force_encoding(Encoding::UTF_8)
    end

    # XXH3-64 (seed 0) of the normalized text as an unsigned decimal string.
    def query_hash(normalized) = Digest::XXH3_64bits.idigest(normalized.b).to_s

    OP = /\A\s*(?:with\b[\s\S]*?\)\s*)?([a-z]+)/i
    TARGET = /\b(?:from|into|update|join|table)\s+((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i

    # [OPERATION, first table] of normalized text, like the Node SDK's querySummary.
    def summary(normalized)
      op = OP.match(normalized)&.[](1)&.upcase.to_s
      t = TARGET.match(normalized)&.[](1)&.delete('"').to_s
      [op, t]
    end

    def attributes(stmt, system: 'sqlite', with_text: false)
      return {} if stmt.nil? || stmt.empty?

      n = normalize(stmt, pg?(system))
      a = { 'db.query.hash' => query_hash(n) }
      op, table = summary(n)
      unless op.empty?
        a['db.operation.name'] = op
        a['db.query.summary'] = table.empty? ? op : "#{op} #{table}"
        a['db.collection.name'] = table unless table.empty?
      end
      a['db.query.text'] = n if with_text
      a
    end
  end
end
