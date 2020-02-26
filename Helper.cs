using Newtonsoft.Json;
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System.Collections;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography;
using System.Net.Http;
using System.Text;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Threading;

namespace omsagent_windows
{
    internal static class Constants
    {
        public const string DockerEndpointBaseUriString = "npipe://./pipe/docker_engine";
        public const string KubernetesServiceAccountTokenFilPath = @"/var/run/secrets/kubernetes.io/serviceaccount/token";
        public const string KubernetesServiceAccountCACertFilPath = @"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";


        // omsagent secret (LA workspace Id, key and domain name)
        public const string OmsAgentSecretDir = @"C:\ProgramData";

        public const string WorkspaceKeyFileName = "KEY";
        public const string WorkspaceIdFileName = "WSID";
        public const string WorkspaceDomain = "DOMAIN";


        public const UInt64 BYTESPERMB = 1048576;
        public const UInt64 CPUTICS = 1000000000;
        public const int KBPERMB = 1024;
        public const int CONTAINER_LIST_QUERY_TIMEOUT_SECONDS = 100;
        public const int IMAGE_LIST_QUERY_TIMEOUT_SECONDS = 100;
        public const int CONTAINER_EVENTS_QUERY_TIMEOUT_SECONDS = 100;
        public const int CONTAINER_INSPECT_QUERY_TIMEOUT_SECONDS = 10;
        public const int CONTAINER_STATS_QUERY_TIMEOUT_SECONDS = 5;
        public const int CONTAINER_LOG_QUERY_TIMEOUT_SECONDS = 10;
        public const int SYTEM_INFO_QUERY_TIMEOUT_SECONDS = 5;

        public const int KUBE_SYSTEM_CONTAINER_IDs_REFRESH_INTERVAL_IN_SECONDS = 300;

        public const int CONTAINER_LOG_UPLOAD_INTERVAL_IN_SECONDS = 60;

        /// <summary>
        /// constants related to masking the secrets in container environment variable
        /// </summary>
        public static string LOGANALYTICS_CONTAINERS_MASK_ENVVAR_NAME = "LOGANALYTICS_CONTAINERS_MASK_ENVVAR_VALUE_REGEX_LIST";
        public static string LOGANALYTICS_CONTAINER_MASKED_VALUE = "[EXCLUDED-BY-CONTAINERMONITORING]";

        public const string CONTAINER_LOG_DATA_TYPE = "CONTAINER_LOG_BLOB";
        public const string CONTAINER_INSIGHTS_IP_NAME = "ContainerInsights";

        public const string DEFAULT_LOG_ANALYTICS_WORKSPACE_DOMAIN = "opinsights.azure.com";

        public const string DEFAULT_SIGNATURE_ALOGIRTHM = "SHA1WithRSA";
    }



    internal static class Helper
    {

        private static int retryCount = 3;
        private static TimeSpan delay = TimeSpan.FromSeconds(5);

        public static X509Certificate2 RegisterAgentWithOMS(string logAnalyticsWorkspaceId, 
            string logAnalyticsWorkspaceKey, string logAnalyticsWorkspaceDomain)
        {
            X509Certificate2 agentCert = null;

            var agentGuid = Guid.NewGuid().ToString("B");

            try
            {
                agentCert = CreateSelfSignedCertificate(agentGuid, logAnalyticsWorkspaceId);

                if (agentCert == null)
                {
                    throw new Exception($"creating self-signed certificate failed for agentGuid : {agentGuid} and workspace: {LogAnalyticsWorkspaceId}");
                }

                Console.WriteLine($"Successfully created self-signed certificate  for agentGuid : {agentGuid} and workspace: {LogAnalyticsWorkspaceId}");

                Console.WriteLine($"Agent Guid : {agentGuid}");

                RegisterWithOmsWithBasicRetryAsync(agentCert, agentGuid,
                    logAnalyticsWorkspaceId,
                    logAnalyticsWorkspaceKey,
                    logAnalyticsWorkspaceDomain);

            
            } catch(Exception ex)
            {
                Console.WriteLine("Registering agent with OMS failed : {0}", ex.Message.ToString());

                throw ex;
            }

            return agentCert;
        }
        /// <summary>
        /// Get the name of the computer
        /// </summary>
        /// <returns>The name of the local computer</returns>
        public static string GetLocalHostName()
        {
            try
            {
                return Dns.GetHostName();
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to get Host DNS name, using Environment.MachineName instead.");
                return Environment.MachineName;
            }
        }

        /// <summary>
        /// Serialize json data to the file
        /// </summary>
        /// <param name="FileName">The JSON file name</param>
        /// <param name="data">The JSON object data</param>
        public static void SerializeData(string FileName, Object data)
        {
            using (var sw = new StreamWriter(FileName))
            {
                var jsonserializer = new JsonSerializer();
                using (JsonWriter jsonWriter = new JsonTextWriter(sw))
                {
                    jsonserializer.Serialize(jsonWriter, data);
                }
            }
        }

        /// <summary>
        /// return true if the docker named pipe npipe://./pipe/docker_engine up and running
        /// this will be false in any of the following scenarios ..
        ///  1. docker engine namedpipe not mounted properly 
        ///  2. docker engine namedpie not accessible
        ///  2. docker not running or crashed on the host 
        ///  3. docker engine namedpipe forcibly turned off
        /// </summary>
        /// <returns></returns>
        public static bool IsDockerNamedPipeUpAndRunning
        {
            get
            {
                return Directory.GetFiles(@"\\.\pipe\").Count(np => np.Equals(@"\\.\pipe\docker_engine")) != 0;
            }
        }


        /// <summary>
        ///  Access Token to make the Kube API calls 
        /// </summary>
        public static string KubeAPIAccessToken
        {
            get
            {
                string serviceAccountToken = string.Empty;

                if (File.Exists(Constants.KubernetesServiceAccountTokenFilPath))
                {
                    serviceAccountToken = File.ReadAllText(Constants.KubernetesServiceAccountTokenFilPath);
                }

                return serviceAccountToken;
            }
        }

        /// <summary>
        /// Kubernetes API Host Url
        /// </summary>
        public static string KubernetesServiceHostUrl
        {
            get
            {
                return "https://" + Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST");
            }
        }

        public static string KubernetesServiceAccountCert
        {
            get
            {
                var caCert = File.Exists(Constants.KubernetesServiceAccountCACertFilPath) ? File.ReadAllText(Constants.KubernetesServiceAccountCACertFilPath) : "";

                if (!string.IsNullOrEmpty(caCert))
                {
                    if (caCert.Contains("BEGIN"))
                    {
                        caCert = caCert.Replace("-----BEGIN CERTIFICATE-----", "");
                    }

                    if (caCert.Contains("END"))
                    {
                        caCert = caCert.Replace("-----END CERTIFICATE-----", "");
                    }

                    caCert = caCert.Trim();
                }

                return caCert;
            }
        }

        public static string LogAnalyticsWorkspaceId
        {
            get
            {
                var logAnalyticsWorkspaceId = string.Empty;

                var workspaceIdFilePath = Path.Combine(Constants.OmsAgentSecretDir, Constants.WorkspaceIdFileName);

                if (File.Exists(workspaceIdFilePath))
                {
                    logAnalyticsWorkspaceId = File.ReadAllText(workspaceIdFilePath).Trim();
                } else
                {
                    Console.WriteLine("Workspace Id file path doesnot exist : {0}", workspaceIdFilePath);
                }

                return logAnalyticsWorkspaceId;

            }
        }

        public static string LogAnalyticsWorkspaceKey
        {
            get
            {
                var logAnalyticsWorkspaceKey = string.Empty;

                var workspaceKeyFilePath = Path.Combine(Constants.OmsAgentSecretDir, Constants.WorkspaceKeyFileName);

                if (File.Exists(workspaceKeyFilePath))
                {
                    logAnalyticsWorkspaceKey = File.ReadAllText(workspaceKeyFilePath).Trim();
                }else
                {
                    Console.WriteLine("Workspace key file path doesnot exist : {0}", workspaceKeyFilePath);
                }

                return logAnalyticsWorkspaceKey;
            }
        }

        public static string LogAnalyticsWorkspaceDomain
        {
            get
            {
                var logAnalyticsWorkspaceDomain = string.Empty;

                var workspaceDomainFilePath = Path.Combine(Constants.OmsAgentSecretDir, Constants.WorkspaceDomain);

                if (File.Exists(workspaceDomainFilePath))
                {
                    logAnalyticsWorkspaceDomain = File.ReadAllText(workspaceDomainFilePath).Trim();
                }

                return logAnalyticsWorkspaceDomain;
            }
        }

        public static void SaveCertificate(X509Certificate2 certificate)
        {
            var userStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            userStore.Open(OpenFlags.ReadWrite);
            userStore.Add(certificate);
            userStore.Close();
        }

        private static X509Certificate2 CreateSelfSignedCertificate(string agentGuid, string logAnalyticsWorkspaceId)
        {
            var random = new SecureRandom();

            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);

            certificateGenerator.SetSerialNumber(serialNumber);

            
            var dirName = string.Format("CN={0}, CN={1}, OU=Microsoft Monitoring Agent, O=Microsoft", logAnalyticsWorkspaceId, agentGuid);

            X509Name certName = new X509Name(dirName);

            certificateGenerator.SetIssuerDN(certName);

            certificateGenerator.SetSubjectDN(certName);

            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);

            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(1));

            const int strength = 2048;

            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();

            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            //certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
            //  new ExtendedKeyUsage(new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth }));

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
              new AuthorityKeyIdentifier(
                  new GeneralNames(new GeneralName(certName)), serialNumber));


            //certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
            //   new AuthorityKeyIdentifier(
            //       SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public),
            //       new GeneralNames(new GeneralName(certName)), serialNumber));
                                                         

            var issuerKeyPair = subjectKeyPair;
            
            var signatureFactory = new Asn1SignatureFactory(Constants.DEFAULT_SIGNATURE_ALOGIRTHM, issuerKeyPair.Private);
            var bouncyCert = certificateGenerator.Generate(signatureFactory);

            // Lets convert it to X509Certificate2
            X509Certificate2 certificate;

            Pkcs12Store store = new Pkcs12StoreBuilder().Build();

            store.SetKeyEntry($"{agentGuid}_key", new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { new X509CertificateEntry(bouncyCert) });

            string exportpw = Guid.NewGuid().ToString("x");

            using (var ms = new MemoryStream())
            {
                store.Save(ms, exportpw.ToCharArray(), random);
                certificate = new X509Certificate2(ms.ToArray(), exportpw, X509KeyStorageFlags.Exportable);
            }
            
            return certificate;
        }

        /// <summary>
        /// get the self-signed certificate from the store
        /// </summary>
        /// <param name="agentGuid"></param>
        /// <param name="logAnalyticsWorkspaceId"></param>
        /// <returns></returns>

        public static X509Certificate2 GetCert(string agentGuid, string logAnalyticsWorkspaceId)
        {
            X509Certificate2 result = null;
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Subject.Contains("{"))
                {
                    if (cert.Subject.ToUpper().Contains(agentGuid.ToUpper()) && cert.Subject.ToUpper().Contains(logAnalyticsWorkspaceId.ToUpper()))
                    {
                        result = cert;
                        break;
                    }
                }
            }
            store.Close();

            return result;
        }


        public static void RegisterWithOms(X509Certificate2 cert, string AgentGuid, string logAnalyticsWorkspaceId, string logAnalyticsWorkspaceKey, string logAnalyticsWorkspaceDomain)
        {
           
                string rawCert = Convert.ToBase64String(cert.GetRawCertData()); //base64 binary
                string hostName = Dns.GetHostName();

                string date = DateTime.Now.ToString("O");

                string xmlContent = "<?xml version=\"1.0\"?>" +
                    "<AgentTopologyRequest xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.microsoft.com/WorkloadMonitoring/HealthServiceProtocol/2014/09/\">" +
                    "<FullyQualfiedDomainName>" 
                     +    hostName 
                    + "</FullyQualfiedDomainName>" +
                    "<EntityTypeId>"
                        + AgentGuid
                    + "</EntityTypeId>" +
                    "<AuthenticationCertificate>"
                      + rawCert
                    + "</AuthenticationCertificate>" +
                    "</AgentTopologyRequest>";

                SHA256 sha256 = SHA256.Create();

                string contentHash = Convert.ToBase64String(sha256.ComputeHash(Encoding.ASCII.GetBytes(xmlContent)));

                string authKey = string.Format("{0}; {1}", logAnalyticsWorkspaceId, Sign(date, contentHash, logAnalyticsWorkspaceKey));


                HttpClientHandler clientHandler = new HttpClientHandler();

                clientHandler.ClientCertificates.Add(cert);

                var client = new HttpClient(clientHandler);

                string url = "https://" + logAnalyticsWorkspaceId + ".oms." + logAnalyticsWorkspaceDomain + "/AgentService.svc/AgentTopologyRequest";

                Console.WriteLine("OMS endpoint Url : {0}", url);

                client.DefaultRequestHeaders.Add("x-ms-Date", date);
                client.DefaultRequestHeaders.Add("x-ms-version", "August, 2014");
                client.DefaultRequestHeaders.Add("x-ms-SHA256_Content", contentHash);
                client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authKey);
                client.DefaultRequestHeaders.Add("user-agent", "MonitoringAgent/OneAgent");
                client.DefaultRequestHeaders.Add("Accept-Language", "en-US");


                HttpContent httpContent = new StringContent(xmlContent, Encoding.UTF8);

                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/xml");


                Console.WriteLine("sent registration request");

                Task<HttpResponseMessage> response = client.PostAsync(new Uri(url), httpContent);

                Console.WriteLine("waiting response for registration request : {0}", response.Result.StatusCode);

                response.Wait();

                Console.WriteLine("registration request processed");

                Console.WriteLine("Response result status code : {0}", response.Result.StatusCode);

                HttpContent responseContent = response.Result.Content;

                string result = responseContent.ReadAsStringAsync().Result;

                Console.WriteLine("Return Result: " + result);

                Console.WriteLine(response.Result);
           
        }

        private static string Sign(string requestdate, string contenthash, string key)
        {
            var signatureBuilder = new StringBuilder();
            signatureBuilder.Append(requestdate);
            signatureBuilder.Append("\n");
            signatureBuilder.Append(contenthash);
            signatureBuilder.Append("\n");
            string rawsignature = signatureBuilder.ToString();

            //string rawsignature = contenthash;

            HMACSHA256 hKey = new HMACSHA256(Convert.FromBase64String(key));
            return Convert.ToBase64String(hKey.ComputeHash(Encoding.UTF8.GetBytes(rawsignature)));
        }


        public static void RegisterWithOmsWithBasicRetryAsync(X509Certificate2 cert, string AgentGuid, string logAnalyticsWorkspaceId, string logAnalyticsWorkspaceKey, string logAnalyticsWorkspaceDomain)
        {
            int currentRetry = 0;

            for (; ; )
            {
                try
                {
                     RegisterWithOms(
                        cert, AgentGuid, logAnalyticsWorkspaceId, logAnalyticsWorkspaceKey,  logAnalyticsWorkspaceDomain);

                    // Return or break.
                    break;
                }
                catch (Exception ex)
                {
                   
                    currentRetry++;

                    // Check if the exception thrown was a transient exception
                    // based on the logic in the error detection strategy.
                    // Determine whether to retry the operation, as well as how
                    // long to wait, based on the retry strategy.
                    if (currentRetry > retryCount)
                    {
                        // If this isn't a transient error or we shouldn't retry,
                        // rethrow the exception.
                        Console.WriteLine("exception occurred : {0}", ex.Message);
                        throw;
                    }
                }

                // Wait to retry the operation.
                // Consider calculating an exponential delay here and
                // using a strategy best suited for the operation and fault.
                Task.Delay(delay);
            }
        }

        // Async method that wraps a

    }

}
