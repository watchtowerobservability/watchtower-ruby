# frozen_string_literal: true

module Watchtower
  # Rails.error subscriber (rescue reporting) and notification hooks for ActiveJob and ActionCable.
  module RailsIntegration
    class ErrorSubscriber
      def report(error, handled:, severity:, context: {}, source: nil)
        attrs = { 'error.handled' => handled, 'error.severity' => severity.to_s }
        attrs['error.source'] = source.to_s if source
        context.each { |k, v| attrs["rails.context.#{k}"] = v.to_s }
        Watchtower.capture_exception(error, attrs)
      end
    end

    EVENTS = { 'perform.active_job' => 'active_job', 'perform_action.action_cable' => 'action_cable' }.freeze

    def self.subscribe_notifications(bus)
      EVENTS.each do |event, source|
        bus.subscribe(event) do |*args|
          err = args.last[:exception_object]
          Watchtower.capture_exception(err, 'error.source' => source) if err
        end
      end
    end
  end
end

if defined?(::Rails::Railtie)
  module Watchtower
    class Railtie < ::Rails::Railtie
      initializer 'watchtower.subscribe' do |app|
        Watchtower.install_exception_hooks
        app.middleware.insert(0, Watchtower::RackMiddleware)
        ::Rails.error.subscribe(Watchtower::RailsIntegration::ErrorSubscriber.new) if ::Rails.respond_to?(:error)
        Watchtower::RailsIntegration.subscribe_notifications(ActiveSupport::Notifications)
      end
    end
  end
end
