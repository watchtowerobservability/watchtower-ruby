# frozen_string_literal: true

module Watchtower
  # Sidekiq server middleware:
  #   Sidekiq.configure_server { |c| c.server_middleware { |m| m.add Watchtower::SidekiqMiddleware } }
  class SidekiqMiddleware
    def call(worker, job, queue)
      yield
    rescue Exception => e # rubocop:disable Lint/RescueException
      Watchtower.capture_exception(e, 'sidekiq.job.class' => worker.class.name.to_s,
                                      'sidekiq.job.id' => job['jid'].to_s, 'sidekiq.queue' => queue.to_s)
      raise
    end
  end
end
