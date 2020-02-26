module OMSAgentHelperModule
  class CaseSensitiveString < String
    def downcase
      self
    end
    def capitalize
      self
    end
    def to_s
      self
    end
  end

  # This file extends the OMS::Common class and with
  # methods shared by the topology and telemetry scripts.
  # It remains separate in order to retain compatibility between
  # plugins from DSC modules and those in the shell bundle.
  class StrongTypedClass
    def self.strongtyped_accessor(name, type)
      # setter
      self.class_eval("def #{name}=(value);
      if !value.is_a? #{type} and !value.nil?
          raise ArgumentError, \"Invalid data type. #{name} should be type #{type}\"
      end
      @#{name}=value
      end")
      # getter
      self.class_eval("def #{name};@#{name};end")
    end
    
    def self.strongtyped_arch(name)
      # setter
      self.class_eval("def #{name}=(value);
      if (value != 'x64' && value != 'x86')
          raise ArgumentError, \"Invalid data for ProcessorArchitecture.\"
      end
      @#{name}=value
      end")
    end
  end

  #Simple class to support interaction with topology script helper method (obj_to_hash)
  class AgentRenewCertificateRequest < StrongTypedClass
    strongtyped_accessor :NewCertificate, String
  end

  class AgentTopologyRequestOperatingSystemTelemetry < StrongTypedClass
    strongtyped_accessor :PercentUserTime, Integer
    strongtyped_accessor :PercentPrivilegedTime, Integer
    strongtyped_accessor :UsedMemory, Integer
    strongtyped_accessor :PercentUsedMemory, Integer
  end

  class AgentTopologyRequestHandler < StrongTypedClass
    require 'gyoku'
    def evaluate_fqdn()
      hostname = `hostname`
      #domainname = `hostname -d 2> /dev/null`
          # if !domainname.nil? and !domainname.empty?
        #   return "#{hostname}.#{domainname}"
      # end
      return hostname
    end

    def handle_request(os_info, entity_type_id, auth_cert)
      topology_request = AgentTopologyRequest.new
      topology_request.FullyQualfiedDomainName = evaluate_fqdn()
      topology_request.EntityTypeId = entity_type_id
      topology_request.AuthenticationCertificate = auth_cert
      body_heartbeat = "<?xml version=\"1.0\"?>\n"
      body_heartbeat.concat(Gyoku.xml({ "AgentTopologyRequest" => {:content! => obj_to_hash(topology_request), :'@xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance", :'@xmlns:xsd' => "http://www.w3.org/2001/XMLSchema", :@xmlns => "http://schemas.microsoft.com/WorkloadMonitoring/HealthServiceProtocol/2014/09/"}}))
      
      return body_heartbeat
    end
  end
  
  class OnboardingHelper
    require 'openssl'
    require 'securerandom'
    require 'gyoku'
    require 'net/http'
    
    require_relative 'oms'
    def initialize
      #Have some sort of logger?
      puts "Initializing OnboardingHelper..."
      @key_path = "C:\\omsagentsecrets\\oms.key"
      @cert_path = "C:\\omsagentsecrets\\oms.crt"
    end
    
    def file_exists_nonempty(file_path)
      return (!file_path.nil? and File.exist?(file_path) and !File.zero?(file_path))
    end
    
    def generate_certs(workspace_id, agent_uuid)
      puts "Agent uuid is " + agent_uuid
      if workspace_id.nil? or agent_uuid.nil? or workspace_id.empty? or agent_uuid.empty?
        puts "Both WORKSPACE_ID and AGENT_GUID must be defined to generate certificates"
        return OMS::MISSING_CONFIG
      end
      
      puts "Generating Certificate..."
      error=nil
      # Set safe certificate permissions before to prevent timing attacks
      key_file = File.new(@key_path, "w")
      cert_file = File.new(@cert_path, "w")
      
      begin
      # Create new private key of 2048 bits
        key = OpenSSL::PKey::RSA.new(2048)
        x509_version = 2  # enable X509 V3 extensions
        two_byte_range = 2**16 - 2  # 2 digit byte range for serial number
        year = 1 * 365 * 24 * 60 * 60  # 365 days validity for certificate
        
        # Generate CSR from new private key
        csr = OpenSSL::X509::Request.new
        csr.version = x509_version
        csr.subject = OpenSSL::X509::Name.new([
          ["CN", workspace_id],
          ["CN", agent_uuid],
          ["OU", "Windows Monitoring Agent"],
          ["O", "Microsoft"]])
        csr.public_key = key.public_key
        csr.sign(key, OpenSSL::Digest::SHA256.new)
        # Self-sign CSR
        csr_cert = OpenSSL::X509::Certificate.new
        csr_cert.serial = SecureRandom.random_number(two_byte_range) + 1
        csr_cert.version = x509_version
        csr_cert.not_before = Time.now
        csr_cert.not_after = Time.now + year
        csr_cert.subject = csr.subject
        csr_cert.public_key = csr.public_key
        csr_cert.issuer = csr_cert.subject  # self-signed
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = csr_cert
        ef.issuer_certificate = csr_cert
        csr_cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
        csr_cert.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
        csr_cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",false))
        csr_cert.sign(key, OpenSSL::Digest::SHA256.new)
        # Write key and cert to files
        key_file.write(key)
        cert_file.write(csr_cert)
      rescue => e
        error = e
      ensure
        key_file.close
        cert_file.close
        puts "Certificate and key have been created...!"
      end
      
      #Check for any error or non-existent or empty files
      if !error.nil?
        puts "Error generating certs: #{error.message}"
        return OMS::ERROR_GENERATING_CERTS
      elsif !file_exists_nonempty(@cert_path) or !file_exists_nonempty(@key_path)
        puts "Error generating certs"
        return OMS::ERROR_GENERATING_CERTS
      end
      
      return 0
    end
    
    # Return the certificate text as a single formatted string
    def get_cert_server(cert_path)
      cert_server = ""
      cert_file_contents = File.readlines(cert_path)
      for i in 1..(cert_file_contents.length-2) # skip first and last line in file
        line = cert_file_contents[i]
        cert_server.concat(line[0..-2])
        if i < (cert_file_contents.length-2)
          cert_server.concat(" ")
        end
      end
      return cert_server
    end
  
    # Updates the CERTIFICATE_UPDATE_ENDPOINT variable and renews certificate if requested
    def apply_certificate_update_endpoint(server_resp)
      update_attr = ""
      cert_update_endpoint = ""
      # Extract the certificate update endpoint from the server response
      endpoint_tag_regex = /\<CertificateUpdateEndpoint.*updateCertificate=\"(?<update_cert>(true|false))\".*(?<cert_update_endpoint>https.*RenewCertificate).*CertificateUpdateEndpoint\>/
      endpoint_tag_regex.match(server_resp) { |match|
      cert_update_endpoint = match["cert_update_endpoint"]
      update_attr = match["update_cert"]
      }
      if cert_update_endpoint.empty?
        puts "Could not extract the update certificate endpoint."
        return OMS::MISSING_CERT_UPDATE_ENDPOINT
      elsif update_attr.empty?
        puts "Could not find the updateCertificate tag in OMS Agent management service telemetry response"
        return OMS::ERROR_EXTRACTING_ATTRIBUTES
      end
    end
      
    # Perform a topology request against the OMS endpoint
    def heartbeat
    
      # Generate the request body
      begin
        body_hb_xml = AgentTopologyRequestHandler.new.handle_request("Windows 10", "a19881c3-d1f5-4f10-81dd-5a9ea0fe009c", get_cert_server(@cert_path))
        # if !xml_contains_telemetry(body_hb_xml)
        #   puts "No Telemetry data was appended to OMS agent management service topology request"
        # end
      rescue => e
        puts "Error when appending Telemetry to OMS agent management service topology request: #{e.message}"
      end
      
      # Form headers
      headers = {}
      req_date = Time.now.utc.strftime("%Y-%m-%dT%T.%N%:z")
      headers[CaseSensitiveString.new("x-ms-Date")] = req_date
      headers["User-Agent"] = get_user_agent
      headers[CaseSensitiveString.new("Accept-Language")] = "en-US"
      # Form POST request and HTTP
      req,http = form_post_request_and_http(headers, "https://5e0e87ea-67ac-4779-b6f7-30173b69112a.oms.opinsights.azure.com/AgentService.svc/LinuxAgentTopologyRequest", body_hb_xml, OpenSSL::X509::Certificate.new(File.open(@cert_path)), OpenSSL::PKey::RSA.new(File.open(@key_path)))
      puts "Generated topology request:\n#{req.body}"
      # Submit request
      begin
        res = nil
        res = http.start { |http_each| http.request(req) }
      rescue => e
        puts "Error sending the topology request to OMS agent management service: #{e.message}"
      end
          
      if !res.nil?
        puts "OMS agent management service topology request response code: #{res.code}"
        if res.code == "200"
          cert_apply_res = apply_certificate_update_endpoint(res.body)
          if cert_apply_res.class != String
            return cert_apply_res
          else
            puts "OMS agent management service topology request success"
            return 0
          end
        else
          puts "Error sending OMS agent management service topology request . HTTP code #{res.code}"
          return OMS::HTTP_NON_200
        end
      else
        puts "Error sending OMS agent management service topology request . No HTTP code"
        return OMS::ERROR_SENDING_HTTP
      end
    end

    def obj_to_hash(obj)
      hash = {}
      obj.instance_variables.each { |var|
      val = obj.instance_variable_get(var)
        next if val.nil?
        if val.is_a?(AgentTopologyRequestOperatingSystemTelemetry) 
          # Put properties of Telemetry class into :attributes["Telemetry"] 
          # so that Gyoku can convert these to attributes for <Telemetry></Telemetry> 
          telemetry_hash = {"Telemetry" => "", :attributes! => {"Telemetry" => obj_to_hash(val)} }
          hash.update(telemetry_hash)
        elsif val.is_a? StrongTypedClass
          hash[var.to_s.delete("@")] = obj_to_hash(val)
        else
          hash[var.to_s.delete("@")] = val
        end
      }
      return hash
    end
    
    # create an HTTP object which uses HTTPS
    def create_secure_http(uri, proxy={})
      if proxy.empty?
        http = Net::HTTP.new( uri.host, uri.port )
      else
        http = Net::HTTP.new( uri.host, uri.port,
        proxy[:addr], proxy[:port], proxy[:user], proxy[:pass])
      end
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = 30
      return http
    end # create_secure_http
    
    # Restore the provided public/private key to the certs files
    def restore_old_certs(cert_old, key_old)
      cert_file = File.open(@cert_path, "w")
      cert_file.write(cert_old)
      cert_file.close
      key_file = File.open(@key_path, "w")
      key_file.write(key_old)
      key_file.close
    end

    # Return a POST request with the specified headers, URI, and body, and an
    #     HTTP to execute that request
    def form_post_request_and_http(headers, uri_string, body, cert, key)
      uri = URI.parse(uri_string)
      req = Net::HTTP::Post.new(uri.request_uri, headers)
      req.body = body
      http = create_secure_http(uri)
      http.cert = cert
      http.key = key
      return req, http
    end

    def register_certs(certificate_update_endpoint)
      # Save old certs
      cert_old = OpenSSL::X509::Certificate.new(File.open(@cert_path))
      key_old = OpenSSL::PKey::RSA.new(File.open(@key_path))
      # Form POST request
      renew_certs_req = AgentRenewCertificateRequest.new
      renew_certs_req.NewCertificate = get_cert_server(@cert_path)
      renew_certs_xml = "<?xml version=\"1.0\"?>\n"
      renew_certs_xml.concat(Gyoku.xml({ "CertificateUpdateRequest" => {:content! => obj_to_hash(renew_certs_req), :'@xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance", :'@xmlns:xsd' => "http://www.w3.org/2001/XMLSchema", :@xmlns => "http://schemas.microsoft.com/WorkloadMonitoring/HealthServiceProtocol/2014/09/"}}))
      req,http = form_post_request_and_http(headers = {}, certificate_update_endpoint, renew_certs_xml, cert_old, key_old)
      puts "Generated renew certificates request:\n#{req.body}"
      # Submit request
      begin
        res = nil
        res = http.start { |http_each| http.request(req) }
      rescue => e
        puts "~~Error renewing certificate: #{e.message}"
        restore_old_certs(cert_old, key_old)
        return OMS::ERROR_SENDING_HTTP
      end
      
      if !res.nil?

        res.each_header do |header, values|
          puts "\t#{header}: #{values.inspect}"
        end
        puts "Body: #{res.body}"

        puts "##Renew certificates response code: #{res.code}"
        if res.code == "200"
          # Do one heartbeat for the server to acknowledge the change
          hb_return = heartbeat
          if hb_return == 0
            puts "Certificates successfully renewed"
          else
            puts "!!Error renewing certificate. Restoring old certs."
            restore_old_certs(cert_old, key_old)
            return hb_return
          end
        else
          puts "@@Error renewing certificate. HTTP code #{res.code}"
          restore_old_certs(cert_old, key_old)
          return OMS::HTTP_NON_200
        end
      else
        puts "Error renewing certificate. No HTTP code"
        return OMS::ERROR_SENDING_HTTP
      end
      
      return 0
    end
  end
end

# Boilerplate syntax for ruby
if __FILE__ == $0
ret_code = 0
  #/subscriptions/72c8e8ca-dc16-47dc-b65c-6b5875eb600a/resourceGroups/kaveeshwin/providers/Microsoft.OperationalInsights/workspaces/kaveeshwin
workspace_id = "5e0e87ea-67ac-4779-b6f7-30173b69112a"
  certificate_update_endpoint = "https://5e0e87ea-67ac-4779-b6f7-30173b69112a.oms.opinsights.azure.com/ConfigurationService.Svc/RenewCertificate"
#Generate agent_uuid and set it in the proper area using securerandom
agent_uuid = "a19881c3-d1f5-4f10-81dd-5a9ea0fe009c" #SecureRandom.uuid
  maintenance = OMSAgentHelperModule::OnboardingHelper.new()
  # Currently generated certs, uncomment when ready to use
#ret_code = maintenance.generate_certs(workspace_id, agent_uuid)
  maintenance.register_certs(certificate_update_endpoint)
  exit ret_code
end
