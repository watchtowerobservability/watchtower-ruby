# Minimal Rack app: WT_INGEST_KEY=... WT_SERVICE=demo bundle exec rackup examples/config.ru
require 'watchtower'

Watchtower.init(Watchtower::Config.from_env)
Watchtower.install_exception_hooks

use Watchtower::RackMiddleware
run ->(env) { env['PATH_INFO'] == '/boom' ? raise('boom') : [200, {}, ['ok']] }
