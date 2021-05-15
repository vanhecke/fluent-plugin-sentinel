# frozen_string_literal: true

require 'resolv'

module Fluent
  module Plugin
    module SentinelHelper
      # Facilitate in-memory storage of hostname lookups.
      class IPcache
        def initialize(refresh_interval_seconds)
          @cache = {}
          @cache_lock = Mutex.new
          @refresh_interval_seconds = refresh_interval_seconds
          @condition = ConditionVariable.new
          @thread = Thread.new(&method(:refresh_cache))
        end

        def get_ip(hostname)
          if @cache.key?(hostname)
            @cache[hostname]
          else
            ip = get_ip_from_socket(hostname)
            @cache_lock.synchronize { @cache[hostname] = ip }
            ip
          end
        end

        private

        def get_ip_from_socket(hostname)
          Resolv.getaddress(hostname)
        rescue ResolvError => e
          # TODO: This might be to verbose for "error" level.
          log.error("Unable to resolve the IP of '#{hostname}': #{e}")
          nil
        end

        def refresh_cache
          loop do
            @cache_lock.synchronize do
              @condition.wait(@cache_lock, @refresh_interval_seconds)
              # Flush the cache completely to prevent it from growing indefinitly
              @cache = {}
            end
          end
        end
      end
    end
  end
end
