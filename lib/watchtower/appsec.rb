# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Watchtower
  # App and API Protection in-app WAF, the same behavior as the Node, Python and Go agents.
  #
  # `Appsec.start` polls `GET /v1/appsec/ruleset` (an ingestion key with scope `probes:read`, ETag,
  # every `poll_s`): the mode (`monitor` or `block`), the enabled pattern rules and the denylist.
  # `Appsec::Middleware` (Rack: Rails, Sinatra) inspects every request before the app: path, query,
  # User-Agent and the other header values, percent-decoded once, against the rules the worker runs
  # over stored spans. A match is recorded on the current span (`appsec.event`, `appsec.rule_id`,
  # `appsec.category`, `appsec.blocked`); in `block` mode, and for denylisted IPs or users in either
  # mode, the request gets 403 problem+json and the app never runs. Install it inside the
  # OpenTelemetry middleware so the server span is current. Rules match case-insensitively; one Ruby
  # cannot compile is skipped. Nothing happens until `start` (or `set_ruleset`) is called.
  module Appsec
    DENYLIST = 'denylist'
    PROBLEM = JSON.generate(type: 'about:blank', title: 'Forbidden', status: 403,
                            detail: 'Request blocked by Watchtower App and API Protection').freeze
    LOCK = Mutex.new
    @state = { mode: 'monitor', rules: [], ip: {}, user: {} }

    module_function

    def expiry(entries)
      Array(entries).each_with_object({}) do |e, h|
        h[e['value']] = (e['expires_at'] || Float::INFINITY) if e.is_a?(Hash) && e['value']
      end
    end

    # Replace the active ruleset (a Hash as the edge serves it; nil clears it).
    def set_ruleset(ruleset)
      r = ruleset || {}
      rules = Array(r['rules']).filter_map do |rule|
        [rule, Regexp.new(rule['pattern'], Regexp::IGNORECASE, timeout: 0.05)]
      rescue RegexpError, TypeError, ArgumentError, NoMethodError
        nil # not portable to Ruby: the worker still evaluates it
      end
      deny = r['denylist'] || {}
      LOCK.synchronize do
        @state = { mode: r['mode'] == 'block' ? 'block' : 'monitor', rules: rules,
                   ip: expiry(deny['ip']), user: expiry(deny['user']) }
      end
    end

    def active?
      s = @state
      !(s[:rules].empty? && s[:ip].empty? && s[:user].empty?)
    end

    def listed?(kind, value, now)
      !value.to_s.empty? && (@state[kind][value] || 0) > now
    end

    # Whether `user_id` is denylisted (call after authentication to refuse a listed user).
    def user_blocked?(user_id, now = Time.now.to_f)
      listed?(:user, user_id, now)
    end

    # Judge one request: a Hash with :path, :query, :user_agent, :headers, :body, :ip, :user.
    def inspect_request(req, now = Time.now.to_f)
      s = @state
      if listed?(:ip, req[:ip], now) || listed?(:user, req[:user], now)
        return { action: 'block', rule_id: DENYLIST, category: 'abuse' }
      end

      s[:rules].each do |rule, rx|
        Array(rule['fields']).each do |f|
          v = req[f.to_sym]
          next if v.nil? || v.empty?

          m = begin
            rx.match(v)
          rescue Regexp::TimeoutError
            nil
          end
          next unless m

          return { action: s[:mode] == 'block' ? 'block' : 'monitor', rule_id: rule['id'].to_s,
                   category: rule['category'].to_s, match: m[0][0, 200] }
        end
      end
      { action: 'allow' }
    end

    def decode(s)
      URI.decode_www_form_component(s.to_s)
    rescue ArgumentError
      s.to_s
    end

    # shortcut: trusts X-Forwarded-For for the client IP; run behind a proxy that overwrites it.
    def from_env(env, user = nil)
      headers = env.select { |k, _| k.start_with?('HTTP_') }.transform_keys { |k| k[5..].tr('_', '-').downcase }
      xff = headers['x-forwarded-for']
      ip = xff ? xff.split(',').first.strip : (headers['x-real-ip'] || env['REMOTE_ADDR'].to_s)
      path = (env['REQUEST_URI'] || env['PATH_INFO'].to_s).split('?', 2).first.to_s
      { path: decode(path), query: decode(env['QUERY_STRING'].to_s.tr('+', ' ')),
        user_agent: headers['user-agent'].to_s,
        headers: headers.reject { |k, _| k == 'user-agent' }.values.join("\n"), ip: ip, user: user }
    end

    def annotate(decision, ip = nil)
      return unless defined?(OpenTelemetry::Trace)

      span = OpenTelemetry::Trace.current_span
      return unless span.recording?

      span.set_attribute('appsec.client_ip', ip) if ip && !ip.empty?
      return if decision[:action] == 'allow'

      span.add_attributes('appsec.event' => true, 'appsec.rule_id' => decision[:rule_id].to_s,
                          'appsec.category' => decision[:category].to_s,
                          'appsec.blocked' => decision[:action] == 'block')
    end

    # Mark the current request as a login attempt; failed ones feed the account-takeover rules.
    def track_login(login, success)
      return unless defined?(OpenTelemetry::Trace)

      span = OpenTelemetry::Trace.current_span
      span.add_attributes('appsec.login' => login.to_s, 'appsec.login.success' => success ? true : false)
      span.set_attribute('appsec.auth', true) if success
    end

    # Rack middleware; `user:` is a callable taking the env that names the caller when known.
    class Middleware
      def initialize(app, user: nil)
        @app = app
        @user = user
      end

      def call(env)
        return @app.call(env) unless Appsec.active?

        req = Appsec.from_env(env, @user&.call(env))
        d = Appsec.inspect_request(req)
        Appsec.annotate(d, req[:ip])
        return @app.call(env) unless d[:action] == 'block'

        [403, { 'content-type' => 'application/problem+json', 'content-length' => PROBLEM.bytesize.to_s }, [PROBLEM]]
      end
    end

    # One poll: [ruleset or nil when unchanged or failed, etag].
    def fetch(endpoint, key, service, etag = '')
      uri = URI("#{endpoint}/v1/appsec/ruleset?#{URI.encode_www_form(service: service)}")
      req = Net::HTTP::Get.new(uri, 'Authorization' => "Bearer #{key}")
      req['If-None-Match'] = etag unless etag.empty?
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 5, read_timeout: 5) { |h| h.request(req) }
      return [nil, etag] unless res.is_a?(Net::HTTPOK)

      [JSON.parse(res.body[0, 4 << 20]), res['ETag'].to_s]
    rescue StandardError
      [nil, etag]
    end

    # Fetch the ruleset now and keep polling in a background thread; returns the thread (kill it to stop).
    def start(endpoint: ENV.fetch('WT_API_URL', 'https://api.watchtower.dev'), key: ENV.fetch('WT_INGEST_KEY', ''),
              service: ENV.fetch('OTEL_SERVICE_NAME', 'unknown'))
      base = endpoint.sub(%r{/+\z}, '')
      etag = ''
      poll = 30
      once = lambda do
        body, etag = fetch(base, key, service, etag)
        if body.is_a?(Hash)
          set_ruleset(body)
          poll = [10, (body['poll_s'] || 30).to_i].max
        end
      end
      once.call
      Thread.new do
        loop do
          sleep poll
          once.call
        end
      end
    end
  end
end
