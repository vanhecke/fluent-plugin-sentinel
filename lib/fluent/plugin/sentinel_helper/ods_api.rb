# frozen_string_literal: true

require 'securerandom'
require 'net/http'
require 'net/https'
require 'openssl'
require 'zlib'
require 'fluent/plugin/sentinel_helper/case_sensitve_string'

module Fluent
  module Plugin
    module SentinelHelper
      # Helpers to send API requests ot ods/log analytics api
      module OdsApi
        # create an HTTPRequest object to ODS
        # parameters:
        #   path: string. path of the request
        #   record: Hash. body of the request
        #   compress: bool. Whether the body of the request should be compressed
        #   extra_header: Hash. extra HTTP headers
        #   serializer: method. serializer of the record
        # returns:
        #   HTTPRequest. request to ODS
        def create_ods_request(path, record, compress, settings, extra_headers = nil, serializer = method(:parse_json_record_encoding))
          headers = extra_headers.nil? ? {} : extra_headers

          arid = settings[:azure_resource_id]
          headers[CaseSensitiveString.new('x-ms-AzureResourceId')] = arid unless arid.to_s.empty?

          headers[CaseSensitiveString.new('x-ms-AzureRegion')] = 'OnPremise'

          omscloud_id = settings[:omscloud_id]
          headers[CaseSensitiveString.new('x-ms-OMSCloudId')] = omscloud_id unless omscloud_id.to_s.empty?

          uuid = settings[:uuid]
          headers[CaseSensitiveString.new('x-ms-UUID')] = uuid unless uuid.to_s.empty?

          headers[CaseSensitiveString.new('X-Request-ID')] = SecureRandom.uuid

          headers['Content-Type'] = 'application/json'
          headers['Content-Encoding'] = 'deflate' if compress

          # TODO : Investigate usage of different ua
          headers['User-Agent'] = 'LinuxMonitoringAgent/0.0.0-0'
          headers[CaseSensitiveString.new('x-ms-app')] = 'LinuxMonitoringAgent'
          headers[CaseSensitiveString.new('x-ms-client-version')] = '0.0.0-0'
          headers[CaseSensitiveString.new('x-ms-client-platform')] = 'Linux'

          req = Net::HTTP::Post.new(path, headers)
          json_msg = serializer.call(record)

          return nil if json_msg.nil?

          req.body = if compress
                       Zlib::Deflate.deflate(json_msg)
                     else
                       json_msg
                     end
          req
        end

        # create an HTTP object to ODS
        def create_ods_http(ods_uri, proxy = {}, key, crt)
          http = create_secure_http(ods_uri, proxy)
          http.cert = crt
          http.key = key
          http
        end

        # parameters:
        #   req: HTTPRequest. request
        #   secure_http: HTTP. HTTPS
        #   ignore404: bool. ignore the 404 error when it's true
        #   return_entire_response: bool. If true, return the entire response object
        # returns:
        #   string. body of the response (or the whole response if return_entire_response is true)
        def start_request(req, secure_http, ignore404: false, return_entire_response: false)
          # Tries to send the passed in request
          # Raises an exception if the request fails.
          # This exception should only be caught by the fluentd engine so that it retries sending this
          res = nil
          res = secure_http.start { |http| http.request(req) }
        rescue => e # rescue all StandardErrors
            # Server didn't respond
          raise RetryRequestException, "Net::HTTP.#{req.method.capitalize} raises exception: #{e.class}, '#{e.message}'"
        else
          raise RetryRequestException, "Failed to #{req.method} at #{req} (res=nil)" if res.nil?

          # TODO: Remove  return_entire_response if not used
          if res.is_a?(Net::HTTPSuccess)
            return res if return_entire_response

            return res.body
          end

          # Todo remove ignore404 if not used
          return '' if ignore404 && res.code == '404'

          if res.code != '200'
            # Retry all failure error codes...
            res_summary = "(request-id=#{req['X-Request-ID']}; class=#{res.class.name}; code=#{res.code}; message=#{res.message}; body=#{res.body};)"
            log.error("HTTP Error: #{res_summary}")
            raise RetryRequestException, "HTTP error: #{res_summary}"
          end
        end

        private

        def create_secure_http(uri, proxy = {})
          http = if proxy.empty?
                   Net::HTTP.new(uri.host, uri.port)
                 else
                   Net::HTTP.new(uri.host, uri.port,
                                 proxy[:addr], proxy[:port],
                                 proxy[:user], proxy[:pass])
                 end
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.open_timeout = 30
          http
        end
      end
    end
  end
end
