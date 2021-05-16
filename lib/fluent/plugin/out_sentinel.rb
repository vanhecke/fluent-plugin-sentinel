# frozen_string_literal: true

require 'fluent/plugin/output'
require 'net/http'
require 'net/https'
require 'uri'
# require 'yajl'
require 'openssl'
require 'fluent/plugin/sentinel_helper/installer'
require 'fluent/plugin/sentinel_helper/case_sensitve_string'
require 'fluent/plugin/sentinel_helper/ods_api'

module Fluent
  module Plugin
    # Fluentd out plugin for Azure Sentinel in Sync-Buffered Mode
    class SentinelOutput < Output
      Fluent::Plugin.register_output('out_sentinel', self)

      helpers :storage

      # config_param :omsadmin_conf_path, :string, :default => '/etc/opt/microsoft/omsagent/conf/omsadmin.conf'
      # config_param :cert_path, :string, :default => '/etc/opt/microsoft/omsagent/certs/oms.crt'
      # config_param :key_path, :string, :default => '/etc/opt/microsoft/omsagent/certs/oms.key'
      # config_param :proxy_conf_path, :string, :default => '/etc/opt/microsoft/omsagent/proxy.conf'

      config_param :compress, :bool, default: true
      config_param :run_in_background, :bool, default: false

      config_param :workspace_id, :string, secret: true
      config_param :shared_key, :string, secret: true

      config_section :storage do
        config_set_default :usage, 'sentstor' # unique value
        config_set_default :@type, 'local'
        config_set_default :persistent, true
      end
      # TODO: Integrate secondary __ChunkErrorHandler__ ?

      def configure(conf)
        super

        # Initialize storage
        @storage = storage_create(usage: 'sentstor')
      end

      def start
        super

        # TODO: Proxy support
        @proxy_config = nil

        if @storage.get(:agent_guid)
          # This is not our first run.
          # Rotate certs and load config.
          # TODO: Rorate certs
          log.error('Not implented yet lol')
          exit
          @agent_guid = @storage.get(:agent_guid, agent_guid)
          @key = @storage.get(:key, key)
          @crt = @storage.get(:crt, crt)
          @settings = Marshal.load(@storage.get(:settings))
        else
          # Fresh install - perform registration from scratch.
          agent_guid = Installer.create_guid
          @key, @crt, @settings = Installer.perform_installation(@workspace_id, @shared_key, agent_guid)

          @storage.put(:agent_guid, agent_guid)
          @storage.put(:key, key)
          @storage.put(:crt, crt)
          @storage.put(:settings, Marshal.dump(settings))
        end
        @ods_endpoint = URI.parse(@settings[:oms_endpoint])
      end

      def formatted_to_msgpack_binary?
        true
      end

      # This method is called when an event reaches to Fluentd.
      # Convert the event to a raw string.
      def format(tag, time, record)
        return '' if record == {}

        return [tag, record].to_msgpack
      end

      # This method is called every flush interval. Send the buffer chunk to OMS.
      # 'chunk' is a buffer chunk that includes multiple formatted
      # NOTE! This method is called by (out_oms) plugin thread not Fluentd's main thread. So IO wait doesn't affect other plugins.
      def write(chunk)
        log.info 'writing chunk'
        # Group records based on their datatype because OMS does not support a single request with multiple datatypes.
        datatypes = {}
        unmergable_records = []
        chunk.msgpack_each do |(tag, record)|
          if record.key?('DataType') && record.key?('IPName')
            key = "#{record['DataType']}.#{record['IPName']}".upcase

            if datatypes.key?(key)
              # Merge instances of the same datatype and ipname together
              datatypes[key]['DataItems'].concat(record['DataItems'])
            elsif record.key?('DataItems')
              datatypes[key] = record
            else
              unmergable_records << [key, record]
            end
          else
            log.warn "Missing DataType or IPName field in record from tag '#{tag}'"
          end
        end

        ret = []
        [datatypes, unmergable_records].each do |list_records|
          list_records.each do |key, records|
            ret << { source: key, event: handle_record(key, records) }
          end
        end

        ret
      end

      def handle_record(key, record)
        log.trace "Handling record : #{key}"
        # extra_headers = {
        #   CaseSensitiveString.new('x-ms-client-request-retry-count') => "#{@num_errors}"
        # }
        req = OdsApi.create_ods_request(@ods_endpoint.path, record, @compress, @settings, extra_headers)

        unless req.nil?
          http = OdsApi.create_ods_http(@ods_endpoint, @proxy_config, @key, @crt)
          start = Time.now
          # This method will raise on failure alerting the engine to retry sending this data
          OdsApi.start_request(req, http)
          ends = Time.now
          time = ends - start
          count = record.key?('DataItems') ? record['DataItems'].size : 1
          log.debug "Success sending #{key} x #{count} in #{time.round(2)}s"
          # write_status_file("true","Sending success")
          # return OMS::Telemetry.push_qos_event(OMS::SEND_BATCH, "true", "", key, record, count, time)
        end
      rescue OdsApi::RetryRequestException => e
        log.info 'Encountered retryable exception. Will retry sending data later.'
        log.debug "Error:'#{e}'"
        # Re-raise the exception to inform the fluentd engine we want to retry sending this chunk of data later.
        # write_status_file("false","Retryable exception")
        raise e.message
      rescue => e
        # We encountered something unexpected. We drop the data because
        # if bad data caused the exception, the engine will continuously
        # try and fail to resend it. (Infinite failure loop)
        msg = "Unexpected exception, dropping data. Error:'#{e}'"
        log.error(msg)
        # write_status_file("false","Unexpected exception")
        msg
      end
    end
  end
end
