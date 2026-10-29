Gem::Specification.new do |s|
  s.name = 'watchtower-sdk'
  s.version = '0.1.0'
  s.summary = 'Thin Watchtower distribution over the OpenTelemetry Ruby SDK'
  s.authors = ['Watchtower']
  s.license = 'Apache-2.0'
  s.homepage = 'https://github.com/watchtowerobservability/watchtower-ruby'
  s.metadata = { 'github_repo' => 'ssh://github.com/watchtowerobservability/watchtower-ruby' }
  s.files = Dir['lib/**/*.rb']
  s.required_ruby_version = '>= 3.1'
  s.add_dependency 'opentelemetry-sdk', '~> 1.5'
  s.add_dependency 'opentelemetry-exporter-otlp', '~> 0.29'
  s.add_development_dependency 'minitest', '~> 5.20'
  s.add_development_dependency 'rake', '~> 13.0'
end
