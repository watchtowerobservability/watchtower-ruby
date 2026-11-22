# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Watchtower
  # Payload and GraphQL capture (APM-016), driven by the capture rules set in Watchtower per service
  # and route (GET /v1/capture-rules?service=, an ingest key with scope probes:read). Opt-in: nothing
  # is fetched or recorded unless WT_CAPTURE_RULES=1 and a rule matches the route. Only text-like
  # bodies are kept, at most the rule's body_bytes (hard cap 8 KiB), after the default secret and
  # PII detectors (a port of the pipeline's redact stage; ingest applies the project's detectors
  # again). Watchtower::RackMiddleware records them.
  # shortcut: rules are fetched once at init; poll with the ETag (poll_s) when live edits matter.
  module Payload
    HARD_MAX = 8192
    R = '[REDACTED]'
    SECRET_KEYS = 'password|passwd|secret|token|access_token|refresh_token|client_secret|api_?key|authorization'
    JSON_SECRET = /("(?:#{SECRET_KEYS})"\s*:\s*)"(?:[^"\\]|\\.)*"/i
    FORM_SECRET = /\b((?:#{SECRET_KEYS})=)[^&\s]*/i
    PATTERNS = [
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/,
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
      %r{bearer\s+[A-Za-z0-9._~+/-]+=*}i,
      /wt[ik]_[a-z0-9]{8}_[A-Za-z0-9_-]{43}/,
      /(?:AKIA|ASIA)[0-9A-Z]{16}/,
      /gh[pousr]_[A-Za-z0-9]{36,}/,
      /[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/,
      /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/,
      /\b\d{3}-\d{2}-\d{4}\b/
    ].freeze
    CARD = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b/
    GQL = /(?:\A|\})\s*(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?/
    TEXT = %r{json|\Atext/|xml|x-www-form-urlencoded|graphql}i

    @rules = []

    class << self
      attr_reader :rules

      def rules=(list)
        @rules = Array(list).select { |r| r.is_a?(Hash) }
      end

      def active? = !@rules.empty?

      # Fetches the service's rules; any failure leaves capture off.
      def load(api_url, key, service)
        uri = URI("#{api_url.sub(%r{/+\z}, '')}/v1/capture-rules?#{URI.encode_www_form(service: service)}")
        req = Net::HTTP::Get.new(uri, 'Authorization' => "Bearer #{key}")
        res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 5, read_timeout: 5) do |h|
          h.request(req)
        end
        self.rules = res.is_a?(Net::HTTPOK) ? JSON.parse(res.body).fetch('rules', []) : []
      rescue StandardError
        self.rules = []
      end

      def glob(pat, str)
        Regexp.new("\\A#{pat.split('*', -1).map { |p| Regexp.escape(p) }.join('.*')}\\z", Regexp::MULTILINE).match?(str)
      end

      def rule_for(route)
        @rules.find { |r| r['route'].to_s.empty? || glob(r['route'], route) }
      end

      def luhn?(str)
        d = str.scan(/\d/).map(&:to_i).reverse
        sum = d.each_with_index.sum { |x, i| i.odd? ? (x * 2 > 9 ? x * 2 - 9 : x * 2) : x }
        d.size >= 13 && (sum % 10).zero?
      end

      # Default secret and PII detectors: secret-named JSON and form fields, keys, tokens, emails,
      # SSNs, Luhn-valid cards.
      def redact(str)
        s = str.gsub(JSON_SECRET) { "#{Regexp.last_match(1)}\"#{R}\"" }.gsub(FORM_SECRET) { "#{Regexp.last_match(1)}#{R}" }
        PATTERNS.each { |re| s = s.gsub(re, R) }
        s.gsub(CARD) { |m| luhn?(m) ? R : m }
      end

      def cap(str, n)
        str.byteslice(0, n).scrub('')
      end

      # Redacts a wider window than it keeps so a secret cut at the edge is still masked.
      def excerpt(str, n) = cap(redact(cap(str, n * 2)), n)

      # [type, name] of a GraphQL document ("{ ... }" is an anonymous query), nil when it is not one.
      def graphql_op(doc)
        d = doc.gsub(/#[^\n]*/, '')
        m = GQL.match(d)
        return [m[1], m[2]] if m

        d.lstrip.start_with?('{') ? ['query', nil] : nil
      end

      def text(body, type)
        return nil if body.nil? || body.empty? || (type && !type.empty? && !TEXT.match?(type))

        body.dup.force_encoding(Encoding::UTF_8).scrub('')
      end

      # Sets the body and GraphQL attributes the rule matching route asks for; no rule, nothing.
      def record(span, route, req_type, req_body, res_type, res_body)
        rule = rule_for(route.to_s)
        return unless rule && span

        n = [rule['body_bytes'].to_i, HARD_MAX].min
        req = text(req_body, req_type)
        res = text(res_body, res_type)
        span.set_attribute('http.request.body', excerpt(req, n)) if n.positive? && req
        span.set_attribute('http.response.body', excerpt(res, n)) if n.positive? && res
        doc, name = graphql_doc(req, req_type)
        op = doc && graphql_op(doc)
        return unless op

        span.set_attribute('graphql.operation.type', op[0])
        span.set_attribute('graphql.operation.name', name || op[1]) if name || op[1]
        span.set_attribute('graphql.document', excerpt(doc, HARD_MAX)) if rule['graphql_query']
      end

      def graphql_doc(req, type)
        return nil unless req
        return [req, nil] if type.to_s.downcase.include?('graphql')

        j = JSON.parse(req)
        return nil unless j.is_a?(Hash) && j['query'].is_a?(String)

        [j['query'], j['operationName'].is_a?(String) ? j['operationName'] : nil]
      rescue JSON::ParserError
        nil
      end
    end
  end
end
