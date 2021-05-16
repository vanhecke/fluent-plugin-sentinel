# frozen_string_literal: true

require 'securerandom'
require 'openssl'
require 'socket'
require 'base64'
require 'net/http'
require 'rexml/document'

module Fluent
  module Plugin
    module SentinelHelper
      # Facilitate 'installation' of the agent.
      # Create keys, register with Azure and generate other required data.
      # This is based on: https://github.com/microsoft/OMS-Agent-for-Linux/tree/master/installer
      module Installer
        # Returns key, crt, oms_admin_conf
        def perform_installation(workspace_id, shared_key, agent_guid)
          url_tld = 'opinsights.azure.com' # TODO: Default value
          key, crt = generate_certs(workspace_id, agent_guid)

          body = generate_req_body(create_guid, crt_path)
          content_hash = Digest::SHA256.base64digest(body)
          request_timestamp = generate_timestamp
          auth_key = get_auth_key(content_hash, shared_key, request_timestamp)
          certificate_update_endpoint, dsc_endpoint = perform_registration(workspace_id, request_timestamp, crt, key, auth_key, content_hash, body)

          oms_admin_conf = {
            workspace_id: workspace_id,
            shared_key: shared_key,
            agent_guid: create_guid,
            certificate_update_endpoint: certificate_update_endpoint,
            dsc_endpoint: dsc_endpoint,
            uuid: get_uuid,
            log_facility: 'local0', # TODO: Default value
            url_tld: url_tld,
            oms_endpoint: "https://#{workspace_id}.ods.#{url_tld}/OperationalData.svc/PostJsonDataItems",
            azure_resource_id: '',
            omscloud_id: ''
          }
          @log.info('Installer completed')
          [key, crt, oms_admin_conf]
        end

        def create_guid
          guid = SecureRandom.uuid
          log.info("New agent guid: #{guid}")
          guid
        end

        private

        # Create the public/private key pair for the agent/workspace
        # From agent_maintance_script.rb in Microsofts' OMS-Agent
        def generate_certs(workspace_id, agent_guid)
          log.info('Generating certificate')

          # Create new private key of 2048 bits
          key = OpenSSL::PKey::RSA.new(2048)

          x509_version = 2 # enable X509 V3 extensions
          two_byte_range = 2**16 - 2 # 2 digit byte range for serial number
          year = 1 * 365 * 24 * 60 * 60 # 365 days validity for certificate

          # Generate CSR from new private key
          csr = OpenSSL::X509::Request.new
          csr.version = x509_version
          csr.subject = OpenSSL::X509::Name.new(
            [
              ['CN', workspace_id],
              ['CN', agent_guid],
              ['OU', 'Linux Monitoring Agent'], # TODO: Change this?
              ['O', 'Microsoft']
            ]
          )
          csr.public_key = key.public_key
          csr.sign(key, OpenSSL::Digest.new('SHA256'))

          # Self-sign CSR
          csr_cert = OpenSSL::X509::Certificate.new
          csr_cert.serial = SecureRandom.random_number(two_byte_range) + 1
          csr_cert.version = x509_version
          csr_cert.not_before = Time.now
          csr_cert.not_after = Time.now + year
          csr_cert.subject = csr.subject
          csr_cert.public_key = csr.public_key
          csr_cert.issuer = csr_cert.subject # self-signed
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = csr_cert
          ef.issuer_certificate = csr_cert
          csr_cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))
          csr_cert.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always', false))
          csr_cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', false))
          csr_cert.sign(key, OpenSSL::Digest.new('SHA256'))

          # Return key and cert
          [key, csr_cert]
        rescue => e
          error = e
          log.error("Error generating certs: #{error.message}")
          exit
        end

        def generate_req_body(agent_guid, cert)
          cert.pop
          cert.shift
          cert = cert.join.chomp
          agent_name = 'fluentd_sentinel'
          version = 0.1 # TODO: Change to gem version
          hostname = Socket.gethostname
          cpu = Gem::Platform.local.cpu
          %{<?xml version="1.0"?>
              <AgentTopologyRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://schemas.microsoft.com/WorkloadMonitoring/HealthServiceProtocol/2014/09/">
              <FullyQualfiedDomainName>#{hostname}</FullyQualfiedDomainName>
              <EntityTypeId>#{agent_guid}</EntityTypeId>
              <AuthenticationCertificate>#{cert}</AuthenticationCertificate>
              <OperatingSystem>
              <InContainer>False</InContainer>
              <Name>#{agent_name}</Name>
              <Version>#{version}</Version>
              <Manufacturer></Manufacturer>
              <Telemetry></Telemetry>
              <ProcessorArchitecture>#{cpu}</ProcessorArchitecture>
              </OperatingSystem>
              </AgentTopologyRequest>
          }
        end

        # should equal to GNU date +%Y-%m-%dT%T.%N%:z used by MSFT
        def generate_timestamp
          Time.now.strftime("%Y-%m-%dT%T.%N%:z")
        end

        # adapted from MSFT's auth_key.rb
        def get_auth_key(content_hash, shared_key, date_str)
          key_decoded = Base64.decode64(shared_key)
          data = "#{date_str}\n#{content_hash}\n"
          hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key_decoded, data)
          Base64.encode64(hmac).strip
        end

        def perform_registration(workspace_id, timestamp, crt, key, auth_key, content_hash, body)
          res = do_registration_request(workspace_id, timestamp, crt, key, auth_key, content_hash, body)
          if res.code.to_i == 200
            # Parse body as XML
            xml = REXML::Document.new(res.body)
            # CERTIFICATE_UPDATE_ENDPOINT
            crt_update_endpoint = REXML::XPath.first(xml, '/LinuxAgentTopologyResponse/CertificateUpdateEndpoint').text
            # DSC_ENDPOINT
            dsc_endpoint = REXML::XPath.first(xml, '/LinuxAgentTopologyResponse/DscConfiguration/Endpoint').text

            [crt_update_endpoint, dsc_endpoint]
          else
            log.error(res.body)
            log.fatal('Agent registration request failed.')
            exit
          end
        end

        def do_registration_request(workspace_id, timestamp, crt, key, auth_key, content_hash, body)
          log.info('sending registration request to AgentService.svc')
          # Create Client
          url_tld = 'opinsights.azure.com' # TODO: Make this dynamic? Maybe for azure for government?
          uri = URI("https://#{workspace_id}.oms.#{url_tld}/AgentService.svc/LinuxAgentTopologyRequest")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.open_timeout = 30
          http.cert = OpenSSL::X509::Certificate.new(crt)
          http.key = OpenSSL::PKey::RSA.new(key)

          # Create Request
          req = Net::HTTP::Post.new(uri)
          req['Accept'] = '*/*'
          # req['Expect'] = '100-continue'
          req['x-ms-Date'] = timestamp
          req['x-ms-version'] = 'August, 2014'
          req['x-ms-SHA256_Content'] = content_hash
          req['authorization'] = "#{workspace_id}; #{auth_key}"
          # TODO: Can we play with this useragent?
          req['user-agent'] = 'LinuxMonitoringAgent/0.0.0-0'
          req['Accept-Language'] = 'en-US'
          req.body = body
          http.request(req)
        end
      end
    end
  end
end
