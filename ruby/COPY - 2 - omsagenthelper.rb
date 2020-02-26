module OMSAgentHelperModule
 
  class OnboardingHelper
    require 'openssl'
    require 'securerandom'
    require 'gyoku'
    require 'net/http'
    require 'uri'
    
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
    
    
RET_CODE=`curl --header "x-ms-Date: $REQ_DATE" \
--header "x-ms-version: August, 2014" \
--header "x-ms-SHA256_Content: $CONTENT_HASH" \
--header "Authorization: $WORKSPACE_ID; $AUTHORIZATION_KEY" \
--header "User-Agent: $USER_AGENT" \
--header "Accept-Language: en-US" \
--insecure \
$CURL_HTTP_COMMAND \
--data-binary @$BODY_ONBOARD \
--cert "$FILE_CRT" --key "$FILE_KEY" \
--output "$RESP_ONBOARD" $CURL_VERBOSE \
--write-out "%{http_code}\n" $PROXY_SETTING \
https://${WORKSPACE_ID}.oms.${URL_TLD}/AgentService.svc/LinuxAgentTopologyRequest` || error=$?


    def register_certs(certificate_update_endpoint)

      #The Workspace nad DOMAIN needs to be set properly and not hardcoded
      uri = URI.parse("https://5e0e87ea-67ac-4779-b6f7-30173b69112a.oms.opinsights.azure.com/AgentService.svc/LinuxAgentTopologyRequest")
      request = Net::HTTP::Get.new(uri)
      request["X-Ms-Date"] = "2020-02-24T00:43:58.213796312+00:00"
      request["X-Ms-Version"] = "August, 2014"
      request["X-Ms-Sha256_content"] = ""
      request["Authorization"] = "5e0e87ea-67ac-4779-b6f7-30173b69112a; nqWJ0bSZo7g5p4hr4QLFqMB438csAzPb74HMUHb8086Ne6lrkF/vVUyg/jHDGWHACaUJVX6W/6hxX2Gh+2Uhcg=="
      request["User-Agent"] = "WindowsMonitoringAgent:1.10.0-1"
      request["Accept-Language"] = "en-US"

      req_options = {
        use_ssl: uri.scheme == "https",
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      }

      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      # response.code
      # response.body
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
