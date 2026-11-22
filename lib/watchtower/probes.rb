# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Watchtower
  # Dynamic probes for running Ruby code (PLT-044), with the same safety model as the Python,
  # Go and browser agents: off until `Probes.start` is called, read-only and bounded.
  #
  # `start` polls `GET /v1/probes/active` (an ingestion key with scope `probes:read`) and hooks
  # every active probe with one TracePoint (`:call` for `Class#method` or `method` probes,
  # `:line` for `file` + `line`), enabled only while a probe is live. A hit reads the frame's
  # locals through `Binding#local_variable_get`, evaluates the probe's condition (a subset with
  # no calls; comparisons only between plain values, so no user method runs), applies the
  # per-minute rate limit, flattens the locals to `code.snapshot.*` (depth at most 3, 8 KiB,
  # 1 KiB per value) without calling user methods, and emits `probe.snapshot`.
  #
  # Kind `span` wraps the method in a current span `probe <method>` (`:call` opens and attaches
  # it, `:return` ends it, error status when the method exits by exception). Kind
  # `span_decoration` renders `capture.tags` (`{a.b}` over the locals or args, plain values only)
  # and sets them on the active span; `wt.*` names are skipped.
  module Probes
    VALUE_MAX = 1024
    TOKEN = /\s*(&&|\|\||==|!=|<=|>=|[<>!()\[\],]|'[^']*'|"[^"]*"|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)/.freeze
    PLAIN = [String, Symbol, Integer, Float, TrueClass, FalseClass, NilClass].freeze
    IVARS = Kernel.instance_method(:instance_variables)
    IVAR_GET = Kernel.instance_method(:instance_variable_get)
    KLASS = Kernel.instance_method(:class)
    EACH_PAIR = Hash.instance_method(:each_pair)
    EACH = Array.instance_method(:each)

    module_function

    def plain?(v)
      PLAIN.any? { |k| v.instance_of?(k) }
    end

    # Compile a condition to a lambda over a Hash of locals; raises ArgumentError outside the subset.
    def compile(src)
      return ->(_v) { true } if src.nil? || src.strip.empty?

      toks = []
      pos = 0
      src = src.rstrip
      while pos < src.length
        m = TOKEN.match(src, pos)
        raise ArgumentError, 'bad condition' if m.nil? || m.begin(0) != pos

        toks << m[1]
        pos = m.end(0)
      end
      Parser.new(toks).root
    end

    def compare(op, x, y)
      case op
      when 'in' then y.is_a?(Array) && plain?(x) && y.any? { |e| plain?(e) && e == x }
      when 'contains' then x.instance_of?(String) && y.instance_of?(String) && x.include?(y)
      else
        return false unless plain?(x) && plain?(y)
        return x == y if op == '=='
        return x != y if op == '!='

        num = x.is_a?(Numeric) && y.is_a?(Numeric)
        return false unless num || (x.instance_of?(String) && y.instance_of?(String))

        { '<' => x < y, '<=' => x <= y, '>' => x > y, '>=' => x >= y }[op]
      end
    end

    # Field `name` (dotted) of a local, through Hash keys and instance variables only.
    def lookup(vars, name)
      name.split('.').reduce(vars) do |o, k|
        if o.instance_of?(Hash) then o.key?(k) ? o[k] : o[k.to_sym]
        elsif o.nil? || plain?(o) then nil
        else
          iv = :"@#{k}"
          IVARS.bind_call(o).include?(iv) ? IVAR_GET.bind_call(o, iv) : nil
        end
      end
    end

    # Recursive-descent parser of the condition subset.
    class Parser
      def initialize(toks)
        @t = toks
        @i = 0
      end

      def root
        e = or_expr
        raise ArgumentError, 'bad condition' unless @i == @t.length

        ->(v) { e.call(v) ? true : false }
      end

      private

      def peek
        @t[@i]
      end

      def eat(s)
        return false unless peek == s

        @i += 1
        true
      end

      def lit(x)
        return { 'true' => true, 'false' => false, 'null' => nil }[x] if %w[true false null].include?(x)
        return x[1..-2] if x.start_with?("'", '"')

        x.include?('.') ? x.to_f : x.to_i
      end

      def atom
        x = peek
        raise ArgumentError, 'bad condition' if x.nil?

        @i += 1
        if x == '('
          e = or_expr
          raise ArgumentError, 'bad condition' unless eat(')')

          return e
        end
        if x == '['
          items = []
          until peek == ']'
            raise ArgumentError, 'bad condition' if peek.nil?

            n = @t[@i]
            @i += 1
            items << lit(n) unless n == ','
          end
          @i += 1
          return ->(_v) { items }
        end
        if x.match?(/\A['"\-\d]/) || %w[true false null].include?(x)
          val = lit(x)
          return ->(_v) { val }
        end
        raise ArgumentError, 'function calls are not allowed' if peek == '('

        ->(v) { Probes.lookup(v, x) }
      end

      def cmp
        a = atom
        %w[== != <= >= < > in contains].each do |op|
          next unless eat(op)

          b = atom
          return ->(v) { Probes.compare(op, a.call(v), b.call(v)) }
        end
        a
      end

      def not_expr
        if eat('!')
          n = not_expr
          return ->(v) { !n.call(v) }
        end
        cmp
      end

      def and_expr
        left = not_expr
        while eat('&&')
          l = left
          r = not_expr
          left = ->(v) { l.call(v) && r.call(v) }
        end
        left
      end

      def or_expr
        left = and_expr
        while eat('||')
          l = left
          r = and_expr
          left = ->(v) { l.call(v) || r.call(v) }
        end
        left
      end
    end

    # Flatten to dotted names without calling user methods: nesting past depth collapses,
    # values are cut to 1 KiB and the total to max_bytes.
    def capture(values, depth, max_bytes)
      out = {}
      used = 0
      put = lambda do |name, s|
        s = s[0, VALUE_MAX]
        next if used + name.bytesize + s.bytesize > max_bytes

        used += name.bytesize + s.bytesize
        out[name] = s
      end
      walk = lambda do |prefix, v, d|
        join = ->(k) { prefix.empty? ? k.to_s : "#{prefix}.#{k}" }
        if plain?(v)
          put.call(prefix, v.nil? ? 'null' : v.to_s.dup)
        elsif d > depth
          put.call(prefix, '[depth limit]')
        elsif v.instance_of?(Hash)
          EACH_PAIR.bind_call(v) { |k, x| walk.call(join.call(k), x, d + 1) }
        elsif v.instance_of?(Array)
          i = -1
          EACH.bind_call(v) { |x| walk.call(join.call(i += 1), x, d + 1) }
        else
          name = KLASS.bind_call(v).name || 'object'
          ivs = IVARS.bind_call(v)
          put.call(prefix, "[#{name}]") if ivs.empty?
          ivs.each { |iv| walk.call(join.call(iv.to_s.delete_prefix('@')), IVAR_GET.bind_call(v, iv), d + 1) }
        end
      end
      walk.call('', values, 0)
      out
    end

    # Fill `{a.b}` from the locals; only plain values render, anything else (or missing) is empty.
    def render(template, vars)
      template.to_s.gsub(/\{([A-Za-z_][\w.]*)\}/) do
        v = lookup(vars, Regexp.last_match(1))
        plain?(v) && !v.nil? ? v.to_s : ''
      end[0, VALUE_MAX]
    end

    def tags(d, vars)
      ((d['capture'] || {})['tags'] || []).each_with_object({}) do |t, out|
        name = t['name'].to_s
        out[name] = render(t['value'], vars) unless name.empty? || name.start_with?('wt.')
      end
    end

    # One live probe.
    Live = Struct.new(:d, :ok, :klass, :meth, :file, :line, :win, :n)

    def live(d)
      loc = d['location'] || {}
      fn = loc['function'].to_s
      klass, _, meth = fn.include?('#') ? fn.rpartition('#') : ['', '', fn]
      Live.new(d, compile(d['condition']), klass, meth.empty? ? nil : meth.to_sym, loc['file'].to_s, loc['line'].to_i, 0, 0)
    end

    # The probe set of one service; `set` replaces it, `poll` refreshes it from the API.
    class ProbeSet
      attr_reader :live

      def initialize(endpoint:, key:, service:, env: '', version: '', emit: nil, now: -> { Time.now.to_f })
        @endpoint = endpoint.sub(%r{/+\z}, '')
        @key = key
        @service = service
        @env = env
        @version = version
        @emit = emit || Probes.method(:default_emit)
        @now = now
        @etag = ''
        @live = []
        @tp = nil
      end

      def set(defs)
        @live = defs.filter_map do |d|
          Probes.live(d)
        rescue ArgumentError, TypeError
          nil # a probe we cannot evaluate is skipped
        end
        install
      end

      def poll
        q = URI.encode_www_form(service: @service, env: @env, version: @version,
                                kinds: 'log,snapshot,metric,span,span_decoration')
        uri = URI("#{@endpoint}/v1/probes/active?#{q}")
        req = Net::HTTP::Get.new(uri, 'Authorization' => "Bearer #{@key}")
        req['If-None-Match'] = @etag unless @etag.empty?
        res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 10, read_timeout: 10) { |h| h.request(req) }
        return unless res.is_a?(Net::HTTPOK)

        @etag = res['ETag'].to_s
        set(JSON.parse(res.body[0, 4 << 20]).fetch('probes', []))
      rescue StandardError => e
        warn "watchtower probes: poll failed: #{e.class}" if ENV['WT_DEBUG']
      end

      # Expiry, per-minute rate and condition; returns the locals when the probe fires.
      def allowed(p, tp)
        t = @now.call
        return if p.d['expires_at'] && t >= p.d['expires_at'].to_f

        b = tp.binding
        return if b.nil?

        vars = b.local_variables.to_h { |n| [n.to_s, b.local_variable_get(n)] }
        minute = (t / 60).to_i
        if p.win != minute
          p.win = minute
          p.n = 0
        end
        return if p.n >= [p.d['max_rate_per_min'].to_i.nonzero? || 60, 60].min || !p.ok.call(vars)

        p.n += 1
        vars
      end

      def hit(p, tp)
        vars = allowed(p, tp)
        return if vars.nil?

        if p.d['kind'] == 'span_decoration'
          span = OpenTelemetry::Trace.current_span if defined?(OpenTelemetry::Trace)
          span.add_attributes(Probes.tags(p.d, vars)) if span&.recording?
          return
        end
        cap = p.d['capture'] || {}
        attrs = { 'probe.id' => p.d['id'].to_s, 'code.function' => tp.method_id.to_s,
                  'code.filepath' => tp.path.to_s, 'code.lineno' => tp.lineno.to_s }
        attrs['probe.message'] = p.d['message'].to_s unless p.d['message'].to_s.empty?
        depth = [(cap['locals_depth'] || 3).to_i, 3].min
        snap = Probes.capture(vars, depth, [(cap['max_bytes'] || 8192).to_i, 8192].min)
        snap.each { |k, v| attrs["code.snapshot.#{k}"] = v }
        @emit.call('probe.snapshot', attrs)
      rescue StandardError
        nil # the app must never fail because of a probe
      end

      # `:call` of a span-probed method: push one entry per call so `:return` pairs up, a span
      # only when the probe fires.
      def span_open(p, tp)
        span = token = nil
        begin
          if defined?(OpenTelemetry::Trace) && allowed(p, tp)
            span = OpenTelemetry.tracer_provider.tracer('watchtower.probes').start_span(
              "probe #{tp.method_id}",
              attributes: { 'probe.id' => p.d['id'].to_s, 'code.function' => tp.method_id.to_s,
                            'code.filepath' => tp.path.to_s, 'code.lineno' => tp.lineno }
            )
            token = OpenTelemetry::Context.attach(OpenTelemetry::Trace.context_with_span(span))
          end
        rescue StandardError
          span = nil # the app must never fail because of a probe
        end
        (Thread.current[:wt_probe_spans] ||= []) << [tp.method_id, span, token]
      end

      # shortcut: an exceptional exit is read from `$!` at `:return` (a probed call made inside a
      # caller's rescue clause reads as failed), and a probe set replaced while a probed call runs
      # leaves that span open; upgrade with Ruby's `:rescue` event when 3.3 is the floor.
      def span_close(tp, err)
        stack = Thread.current[:wt_probe_spans]
        return unless stack&.last&.first == tp.method_id

        _, span, token = stack.pop
        return if span.nil?

        if err
          span.record_exception(err)
          span.status = OpenTelemetry::Trace::Status.error(err.class.name)
        end
        span.finish
        OpenTelemetry::Context.detach(token)
      rescue StandardError
        nil
      end

      private

      def install
        @tp&.disable
        @tp = nil
        return if @live.empty?

        # span probes first, so a function decoration of the same method tags the probe span
        funcs = @live.select(&:meth).sort_by { |p| p.d['kind'] == 'span' ? 0 : 1 }.group_by(&:meth)
        spans = @live.select { |p| p.meth && p.d['kind'] == 'span' }.group_by(&:meth)
        # a span needs a method; a line-located span probe is ignored
        lines = @live.reject { |p| p.meth || p.d['kind'] == 'span' }
                     .select { |p| p.line.positive? && !p.file.empty? }.group_by(&:line)
        events = []
        events << :call unless funcs.empty?
        events << :return unless spans.empty?
        events << :line unless lines.empty?
        @tp = TracePoint.new(*events) do |tp|
          owner = tp.defined_class&.name.to_s
          if tp.event == :call
            (funcs[tp.method_id] || []).each do |p|
              next unless p.klass.empty? || owner == p.klass

              p.d['kind'] == 'span' ? span_open(p, tp) : hit(p, tp)
            end
          elsif tp.event == :return
            n = (spans[tp.method_id] || []).count { |p| p.klass.empty? || owner == p.klass }
            n.times { span_close(tp, $!) }
          else
            (lines[tp.lineno] || []).each { |p| hit(p, tp) if tp.path.end_with?(p.file) }
          end
        end
        @tp.enable
      end
    end

    def default_emit(name, attrs)
      if defined?(OpenTelemetry::Trace)
        span = OpenTelemetry::Trace.current_span
        span.add_event(name, attributes: attrs) if span.recording?
      end
      warn "#{name} #{JSON.generate(attrs)}" if ENV['WT_PROBES_LOG'] == '1'
    end

    # Poll active probes in a background thread; returns the ProbeSet. Nothing is traced until the
    # API returns a live probe.
    def start(endpoint: ENV.fetch('WT_API_URL', 'https://api.watchtower.dev'), key: ENV.fetch('WT_INGEST_KEY', ''),
              service: ENV.fetch('OTEL_SERVICE_NAME', 'unknown'), env: '', version: '', interval: 30, emit: nil)
      s = ProbeSet.new(endpoint: endpoint, key: key, service: service, env: env, version: version, emit: emit)
      Thread.new do
        loop do
          s.poll
          sleep [interval, 5].max
        end
      end
      s
    end
  end
end
