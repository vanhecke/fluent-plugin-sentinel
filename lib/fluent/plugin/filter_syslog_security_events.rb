# frozen_string_literal: true

require 'fluent/plugin/filter'
require 'fluent/plugin/sentinel_helper/ipcache'

# Original: https://github.com/microsoft/OMS-Agent-for-Linux/blob/fd7f62d8880bda6b197f9372f346981bbcc73216/source/code/plugins/filter_syslog_security.rb

module Fluent
  module Plugin
    # Fluentd filter plugin for CEF over syslog data
    class SyslogSecurityEventsFilter < Filter
      include SentinelHelper::IPcache

      Fluent::Plugin.register_filter('filter_syslog_security', self)

      # def initialize
      #   super
      #   # require_relative("omslog")
      #   # require_relative("oms_common")
      #   # require_relative("security_lib")
      # end

      config_param(:ip_cache_refresh_interval, :integer, default: 300)

      # Interval in seconds to refresh the cache
      def configure(conf)
        super
        @ip_cache = IPcache.new(@ip_cache_refresh_interval)
      end

      def filter(tag, time, record)
        ident = get_ident(record['ident'])
        data_type = get_data_type(ident)
        return nil if data_type.nil?

        tags = tag.split('.')

        # Use Time.now, because it is the only way to get subsecond precision in version 0.12.
        # The time may be slightly in the future from the ingestion time.
        new_record = {
          'ident'     => ident,
          'Timestamp' => fast_utc_to_iso8601_format(Time.now.utc),
          'EventTime' => fast_utc_to_iso8601_format(Time.at(time).utc),
          'Message'   => "#{ident}: #{record['message']}",
          'Facility'  => tags[tags.size - 2],
          'Severity'  => tags[tags.size - 1],
          'Host'      => record['host']
        }

        new_record['HostIP'] = get_ip(record['host']) if get_ip(record['host'])

        if host_ip.nil?
          # TODO : Too verbose?
          log.warn("Failed to get the IP for #{record['host']}.")
        else
          new_record['HostIP'] = host_ip
        end

        {
          'DataType' => data_type,
          'IPName' => 'Security',
          'DataItems' => [new_record]
        }
      end

      private

      def get_ident(ident)
        return 'CEF' if ident.include?('CEF')

        return ident if ident.include?('%ASA')

        log.warn("Failed to find ident: '#{ident}'")
        nil
      end

      def get_data_type(ident)
        return nil if ident.nil?
        return 'SECURITY_CEF_BLOB' if ident.start_with?('CEF')

        return 'SECURITY_CISCO_ASA_BLOB' if ident.start_with?('%ASA')

        log.warn("Failed to find data type for record with ident: '#{ident}'")
        nil
      end

      def fast_utc_to_iso8601_format(utctime, fraction_digits = 3)
        utctime.strftime("%FT%T.%#{fraction_digits}NZ")
      end
    end
  end
end
