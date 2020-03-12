package main

// import (
// 	"../include/fluent-bit-go/output"
// )
import (
	"C"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"
	"bytes"
	"net/http"
	"log"
	"sync"
	"crypto/tls"

	"encoding/base64"
	"errors"
	"strconv"

	"github.com/fluent/fluent-bit-go/output"

	"github.com/Microsoft/ApplicationInsights-Go/appinsights"
	"github.com/microsoft/ApplicationInsights-Go/appinsights/contracts"


	
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// "k8s.io/client-go/kubernetes"
	// "k8s.io/client-go/rest"
)

var (
	// ContainerLogTelemetryMutex read and write mutex access to the Container Log Telemetry
	ContainerLogTelemetryMutex = &sync.Mutex{}
)

var (
	// FLBLogger stream
	FLBLogger = createLogger()
	// Log wrapper function
	Log = FLBLogger.Printf
)

func createLogger() *log.Logger {
	var logfile *os.File
	path := "/var/opt/microsoft/docker-cimprov/log/fluent-bit-out-oms-runtime.log"
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("File Exists. Opening file in append mode...\n")
		logfile, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			SendException(err.Error())
			fmt.Printf(err.Error())
		}
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("File Doesnt Exist. Creating file...\n")
		logfile, err = os.Create(path)
		if err != nil {
			SendException(err.Error())
			fmt.Printf(err.Error())
		}
	}

	logger := log.New(logfile, "", 0)

	logger.SetOutput(&lumberjack.Logger{
		Filename:   path,
		MaxSize:    10, //megabytes
		MaxBackups: 1,
		MaxAge:     28,   //days
		Compress:   true, // false by default
	})

	logger.SetFlags(log.Ltime | log.Lshortfile | log.LstdFlags)
	return logger
}

//export FLBPluginRegister
func FLBPluginRegister(ctx unsafe.Pointer) int {
	return output.FLBPluginRegister(ctx, "oms", "OMS GO!")
}

//export FLBPluginInit
// (fluentbit will call this)
// ctx (context) pointer to fluentbit context (state/ c code)
func FLBPluginInit(ctx unsafe.Pointer) int {
	Log("Initializing out_oms go plugin for fluentbit")
	agentVersion := "ciWindowsPrivatePreview"//os.Getenv("AGENT_VERSION")
	// if strings.Compare(strings.ToLower(os.Getenv("CONTROLLER_TYPE")), "replicaset") == 0 {
	// 	Log("Using %s for plugin config \n", ReplicaSetContainerLogPluginConfFilePath)
	// 	InitializePlugin(ReplicaSetContainerLogPluginConfFilePath, agentVersion)
	// } else {
		//Log("Using %s for plugin config \n", DaemonSetContainerLogPluginConfFilePath)
		// InitializePlugin(DaemonSetContainerLogPluginConfFilePath, agentVersion)
		InitializePlugin("", agentVersion)
	// }
	// enableTelemetry := output.FLBPluginConfigKey(ctx, "EnableTelemetry")
	// if strings.Compare(strings.ToLower(enableTelemetry), "true") == 0 {
		telemetryPushInterval := "300"//output.FLBPluginConfigKey(ctx, "TelemetryPushIntervalSeconds")
		go SendContainerLogPluginMetrics(telemetryPushInterval)
	// } else {
	// 	Log("Telemetry is not enabled for the plugin %s \n", output.FLBPluginConfigKey(ctx, "Name"))
	// 	return output.FLB_OK
	// }
	CreateHTTPClient()
	return output.FLB_OK
}
var (
	// HTTPClient for making POST requests to OMSEndpoint
	HTTPClient http.Client
	// OMSEndpoint ingestion endpoint
	OMSEndpoint string
)

//export FLBPluginFlush
func FLBPluginFlush(data unsafe.Pointer, length C.int, tag *C.char) int {
	//log.Printf("FLBPluginFlush is starting...")


	var ret int
	var record map[interface{}]interface{}
	var records []map[interface{}]interface{}

	// Create Fluent Bit decoder
	dec := output.NewDecoder(data, int(length))

	// Iterate Records
	for {
		// Extract Record
		ret, _, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}
		records = append(records, record)
	}

	incomingTag := strings.ToLower(C.GoString(tag))
	if strings.Contains(incomingTag, "oms.container.log.flbplugin") {
		// This will also include populating cache to be sent as for config events
		return PushToAppInsightsTraces(records, appinsights.Information, incomingTag)
	} 
	// else if strings.Contains(incomingTag, "oms.container.perf.telegraf") {
	// 	return PostTelegrafMetricsToLA(records)
	// }

	//log.Printf("I'm calling PostDataHelper...")

	return PostDataHelper(records)
}


// FLBPluginExit exits the plugin
func FLBPluginExit() int {
	ContainerLogTelemetryTicker.Stop()
	// ContainerImageNameRefreshTicker.Stop()
	return output.FLB_OK
}

// DataItem represents the object corresponding to the json that is sent by fluentbit tail plugin
type DataItem struct {
	LogEntry              string `json:"LogEntry"`
	LogEntrySource        string `json:"LogEntrySource"`
	LogEntryTimeStamp     string `json:"LogEntryTimeStamp"`
	LogEntryTimeOfCommand string `json:"TimeOfCommand"`
	ID                    string `json:"Id"`
	Image                 string `json:"Image"`
	Name                  string `json:"Name"`
	SourceSystem          string `json:"SourceSystem"`
	Computer              string `json:"Computer"`
}

// ContainerLogBlob represents the object corresponding to the payload that is sent to the ODS end point
type ContainerLogBlob struct {
	DataType  string     `json:"DataType"`
	IPName    string     `json:"IPName"`
	DataItems []DataItem `json:"DataItems"`
}

// DataType for Container Log
const ContainerLogDataType = "CONTAINER_LOG_BLOB"

// IPName for Container Log
const IPName = "Containers"

// ToString converts an interface into a string
func ToString(s interface{}) string {
	switch t := s.(type) {
	case []byte:
		// prevent encoding to base64
		return string(t)
	default:
		return ""
	}
}

// CreateHTTPClient used to create the client for sending post requests to OMSEndpoint
func CreateHTTPClient() {
	cert, err := tls.LoadX509KeyPair("C:\\oms.crt", "C:\\oms.key")
	if err != nil {
		// message := fmt.Sprintf("Error when loading cert %s", err.Error())
		// SendException(message)
		// time.Sleep(30 * time.Second)
		// Log(message)
		log.Fatalf("Error when loading cert %s", err.Error())
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	HTTPClient = http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// log.Printf("Successfully created HTTP Client")
}

// GetContainerIDK8sNamespacePodNameFromFileName Gets the container ID, k8s namespace and pod name From the file Name
// sample filename kube-proxy-dgcx7_kube-system_kube-proxy-8df7e49e9028b60b5b0d0547f409c455a9567946cf763267b7e6fa053ab8c182.log
func GetContainerIDK8sNamespacePodNameFromFileName(filename string) (string, string, string) {
	id := ""
	ns := ""
	podName := ""

	start := strings.LastIndex(filename, "-")
	end := strings.LastIndex(filename, ".")

	if start >= end || start == -1 || end == -1 {
		id = ""
	} else {
		id = filename[start+1 : end]
	}

	start = strings.Index(filename, "_")
	end = strings.LastIndex(filename, "_")

	if start >= end || start == -1 || end == -1 {
		ns = ""
	} else {
		ns = filename[start+1 : end]
	}

	start = strings.Index(filename, "/containers/")
	end = strings.Index(filename, "_")

	if start >= end || start == -1 || end == -1 {
		podName = ""
	} else {
		podName = filename[(start + len("/containers/")):end]
	}

	return id, ns, podName
}



// PostDataHelper sends data to the OMS endpoint
func PostDataHelper(tailPluginRecords []map[interface{}]interface{}) int {
	start := time.Now()
	var dataItems []DataItem

	var maxLatency float64
	var maxLatencyContainer string

	// log.Printf("PostDataHelper starts")

	var computer string = os.Getenv("CI_HOSTNAME")

	for _, record := range tailPluginRecords {
		containerID, k8sNamespace, _ := GetContainerIDK8sNamespacePodNameFromFileName(ToString(record["filepath"]))

		// Ignore 
		if strings.EqualFold("omsagent-private-preview-namespace", k8sNamespace) {
			log.Printf("We're reading from the private preview namespace")
		}

		// containerID := "388b1a08956c78beab8cbaea5168d89a1e76c019d9ce53994bea50dff3457b0a"
		// _ = "podname"
		logEntrySource := ToString(record["stream"]);

		stringMap := make(map[string]string)

		stringMap["LogEntry"] = ToString(record["log"])
		stringMap["LogEntrySource"] = logEntrySource
		stringMap["LogEntryTimeStamp"] = ToString(record["time"])
		stringMap["SourceSystem"] = "Containers"
		stringMap["Id"] = containerID
		stringMap["Image"] = "[ImageName-notavailableyet]"
		stringMap["Name"] = "[ContainerName-notavailbleyet]"

		var dataItem DataItem
		dataItem = DataItem{
			ID:                    stringMap["Id"],
			LogEntry:              stringMap["LogEntry"],
			LogEntrySource:        stringMap["LogEntrySource"],
			LogEntryTimeStamp:     stringMap["LogEntryTimeStamp"],
			// LogEntryTimeOfCommand: stringMap["LogEntryTimeStamp"], // start.Format(time.RFC3339) -> This is the value in the linux side
			LogEntryTimeOfCommand: start.Format(time.RFC3339),
			SourceSystem:          stringMap["SourceSystem"],
			Computer:              computer,
			Image:                 stringMap["Image"],
			Name:                  stringMap["Name"],
		
		}

		FlushedRecordsSize += float64(len(stringMap["LogEntry"]))

		dataItems = append(dataItems, dataItem)
		if dataItem.LogEntryTimeStamp != "" {
			loggedTime, e := time.Parse(time.RFC3339, dataItem.LogEntryTimeStamp)
			if e != nil {
				message := fmt.Sprintf("Error while converting LogEntryTimeStamp for telemetry purposes: %s", e.Error())
				Log(message)
				SendException(message)
			} else {
				ltncy := float64(start.Sub(loggedTime) / time.Millisecond)
				if ltncy >= maxLatency {
					maxLatency = ltncy
					maxLatencyContainer = dataItem.Name + "=" + dataItem.ID
				}
			}
		}


		e, err := json.Marshal(dataItem)
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(string(e))
		//dataItems = append(dataItems, dataItem)
	}

	if len(dataItems) > 0 {
		logEntry := ContainerLogBlob{
			DataType:  ContainerLogDataType,
			IPName:    IPName,
			DataItems: dataItems}

		marshalled, err := json.Marshal(logEntry)
		if err != nil {
			message := fmt.Sprintf("Error while Marshalling log Entry: %s", err.Error())
			Log(message)
			SendException(message)
			return output.FLB_OK
		}

		loganalyticsWorkspaceID := os.Getenv("CI_WSID")
		logAnalyticsDomain := os.Getenv("CI_DOMAIN")

		if len(loganalyticsWorkspaceID) == 0 {
			log.Printf("loganalyticsWorkspaceID is empty : Please set the environment variable CI_WSID to it.")
			return output.FLB_RETRY
		}	
	
		if len(logAnalyticsDomain) == 0 {
			log.Printf("logAnalyticsDomain is empty : Please set the environment variable CI_DOMAIN to it.")
			return output.FLB_RETRY
		}
	
		// kaveeshwin - la workspace in comment below
		// OMSEndpoint := "https://5e0e87ea-67ac-4779-b6f7-30173b69112a.ods.opinsights.azure.com/OperationalData.svc/PostJsonDataItems"
		OMSEndpoint := "https://" + loganalyticsWorkspaceID + ".ods." + logAnalyticsDomain + "/OperationalData.svc/PostJsonDataItems"

		req, _ := http.NewRequest("POST", OMSEndpoint, bytes.NewBuffer(marshalled))

		req.Header.Set("Content-Type", "application/json")
		// expensive to do string len for every request, so use a flag
		// if ResourceCentric == true {
		// 	req.Header.Set("x-ms-AzureResourceId", ResourceID)
		// }

		//log.Printf("Sending HTTP Request")

		resp, err := HTTPClient.Do(req)
		elapsed := time.Since(start)

		if err != nil {
			message := fmt.Sprintf("Error when sending request %s \n", err.Error())
			Log(message)
			// Commenting this out for now. TODO - Add better telemetry for ods errors using aggregation
			//SendException(message)
			Log("Failed to flush %d records after %s", len(dataItems), elapsed)
			log.Printf("%s \n", err.Error())
			return output.FLB_RETRY
		}

		if resp == nil || resp.StatusCode != 200 {
			if resp != nil {
				log.Printf("Status %s Status Code %d", resp.Status, resp.StatusCode)
			}
			return output.FLB_RETRY
		}

		//log.Printf("Status code == %s", resp.StatusCode)

		//log.Printf("Closing http")

		defer resp.Body.Close()
		numRecords := len(dataItems)
		Log("PostDataHelper::Info::Successfully flushed %d records in %s", numRecords, elapsed)
		ContainerLogTelemetryMutex.Lock()
		FlushedRecordsCount += float64(numRecords)
		FlushedRecordsTimeTaken += float64(elapsed / time.Millisecond)

		if maxLatency >= AgentLogProcessingMaxLatencyMs {
			AgentLogProcessingMaxLatencyMs = maxLatency
			AgentLogProcessingMaxLatencyMsContainer = maxLatencyContainer
		}

		ContainerLogTelemetryMutex.Unlock()	
	}

	return output.FLB_OK
}

// InitializePlugin reads and populates plugin configuration
func InitializePlugin(pluginConfPath string, agentVersion string) {

	// StdoutIgnoreNsSet = make(map[string]bool)
	// StderrIgnoreNsSet = make(map[string]bool)
	// ImageIDMap = make(map[string]string)
	// NameIDMap = make(map[string]string)
	// // Keeping the two error hashes separate since we need to keep the config error hash for the lifetime of the container
	// // whereas the prometheus scrape error hash needs to be refreshed every hour
	// ConfigErrorEvent = make(map[string]KubeMonAgentEventTags)
	// PromScrapeErrorEvent = make(map[string]KubeMonAgentEventTags)
	// // Initilizing this to true to skip the first kubemonagentevent flush since the errors are not populated at this time
	// skipKubeMonEventsFlush = true

	// enrichContainerLogsSetting := os.Getenv("AZMON_CLUSTER_CONTAINER_LOG_ENRICH")
	// 	if (strings.Compare(enrichContainerLogsSetting, "true") == 0) {
	// 		enrichContainerLogs = true
	// 		Log("ContainerLogEnrichment=true \n")
	// 	} else {
	// 		enrichContainerLogs = false
	// 		Log("ContainerLogEnrichment=false \n")
	// 	}

	// pluginConfig, err := ReadConfiguration(pluginConfPath)
	// if err != nil {
	// 	message := fmt.Sprintf("Error Reading plugin config path : %s \n", err.Error())
	// 	Log(message)
	// 	SendException(message)
	// 	time.Sleep(30 * time.Second)
	// 	log.Fatalln(message)
	// }

	// omsadminConf, err := ReadConfiguration(pluginConfig["omsadmin_conf_path"])
	// if err != nil {
	// 	message := fmt.Sprintf("Error Reading omsadmin configuration %s\n", err.Error())
	// 	Log(message)
	// 	SendException(message)
	// 	time.Sleep(30 * time.Second)
	// 	log.Fatalln(message)
	// }
	OMSEndpoint = os.Getenv("CI_DOMAIN")//omsadminConf["OMS_ENDPOINT"]
	Log("OMSEndpoint %s", OMSEndpoint)

	//WorkspaceID := os.Getenv("CI_WSID")
	// ResourceID := os.Getenv("customResourceId")

	// if len(ResourceID) > 0 {
	// 	//AKS Scenario
	// 	ResourceCentric = true
	// 	splitted := strings.Split(ResourceID, "/")
	// 	ResourceName = splitted[len(splitted)-1]
	// 	Log("ResourceCentric: True")
	// 	Log("ResourceID=%s", ResourceID)
	// 	Log("ResourceName=%s", ResourceID)
	// }
	// if ResourceCentric == false {
	// 	//AKS-Engine/hybrid scenario
	// 	ResourceName = os.Getenv(ResourceNameEnv)
	// 	ResourceID = ResourceName
	// 	Log("ResourceCentric: False")
	// 	Log("ResourceID=%s", ResourceID)
	// 	Log("ResourceName=%s", ResourceName)
	// }

	// // Initialize image,name map refresh ticker
	// containerInventoryRefreshInterval, err := strconv.Atoi(pluginConfig["container_inventory_refresh_interval"])
	// if err != nil {
	// 	message := fmt.Sprintf("Error Reading Container Inventory Refresh Interval %s", err.Error())
	// 	Log(message)
	// 	SendException(message)
	// 	Log("Using Default Refresh Interval of %d s\n", defaultContainerInventoryRefreshInterval)
	// 	containerInventoryRefreshInterval = defaultContainerInventoryRefreshInterval
	// }
	// Log("containerInventoryRefreshInterval = %d \n", containerInventoryRefreshInterval)
	// ContainerImageNameRefreshTicker = time.NewTicker(time.Second * time.Duration(containerInventoryRefreshInterval))

	// Log("kubeMonAgentConfigEventFlushInterval = %d \n", kubeMonAgentConfigEventFlushInterval)
	// KubeMonAgentConfigEventsSendTicker = time.NewTicker(time.Minute * time.Duration(kubeMonAgentConfigEventFlushInterval))

	// Populate Computer field
	// containerHostName, err := ioutil.ReadFile(pluginConfig["container_host_file_path"])
	// if err != nil {
	// 	// It is ok to log here and continue, because only the Computer column will be missing,
	// 	// which can be deduced from a combination of containerId, and docker logs on the node
	// 	message := fmt.Sprintf("Error when reading containerHostName file %s.\n It is ok to log here and continue, because only the Computer column will be missing, which can be deduced from a combination of containerId, and docker logs on the nodes\n", err.Error())
	// 	Log(message)
	// 	SendException(message)
	// }
	Computer := os.Getenv("CI_HOSTNAME")//strings.TrimSuffix(ToString(containerHostName), "\n")
	Log("Computer == %s \n", Computer)

	ret, err := InitializeTelemetryClient(agentVersion)
	if ret != 0 || err != nil {
		message := fmt.Sprintf("Error During Telemetry Initialization :%s", err.Error())
		fmt.Printf(message)
		Log(message)
	}

	// // Initialize KubeAPI Client
	// config, err := rest.InClusterConfig()
	// if err != nil {
	// 	message := fmt.Sprintf("Error getting config %s.\nIt is ok to log here and continue, because the logs will be missing image and Name, but the logs will still have the containerID", err.Error())
	// 	Log(message)
	// 	SendException(message)
	// }

	// ClientSet, err = kubernetes.NewForConfig(config)
	// if err != nil {
	// 	message := fmt.Sprintf("Error getting clientset %s.\nIt is ok to log here and continue, because the logs will be missing image and Name, but the logs will still have the containerID", err.Error())
	// 	SendException(message)
	// 	Log(message)
	// }

	// PluginConfiguration = pluginConfig

	CreateHTTPClient()

	// if strings.Compare(strings.ToLower(os.Getenv("CONTROLLER_TYPE")), "daemonset") == 0 {
	// 	populateExcludedStdoutNamespaces()
	// 	populateExcludedStderrNamespaces()
	// 	if enrichContainerLogs == true {
	// 		Log("ContainerLogEnrichment=true; starting goroutine to update containerimagenamemaps \n")
	// 		go updateContainerImageNameMaps()
	// 	} else {
			Log("ContainerLogEnrichment=false \n")
	// 	}

	// 	// Flush config error records every hour
	// 	go flushKubeMonAgentEventRecords()
	// } else {
	// 	Log("Running in replicaset. Disabling container enrichment caching & updates \n")
	// }

}


func main() {
}



// package main


// import (
// 	"C"
// 	"unsafe"
// )

// import "../include/fluent-bit-go/output"


// // //export FLBPluginRegister
// func FLBPluginRegister(ctx unsafe.Pointer) int {
// 	return output.FLBPluginRegister(ctx, "oms", "OMS GO!")
// }

// //export FLBPluginInit
// func FLBPluginInit(plugin unsafe.Pointer) int {
//     // Gets called only once for each instance you have configured.
//     return output.FLB_OK
// }

// //export FLBPluginFlushCtx
// func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
//     // Gets called with a batch of records to be written to an instance.
//     return output.FLB_OK
// }

// //export FLBPluginExit
// func FLBPluginExit() int {
// 	return output.FLB_OK
// }

// func main() {
// }


var (
	// FlushedRecordsCount indicates the number of flushed log records in the current period
	FlushedRecordsCount float64
	// FlushedRecordsSize indicates the size of the flushed records in the current period
	FlushedRecordsSize float64
	// FlushedRecordsTimeTaken indicates the cumulative time taken to flush the records for the current period
	FlushedRecordsTimeTaken float64
	// This is telemetry for how old/latent logs we are processing in milliseconds (max over a period of time)
	AgentLogProcessingMaxLatencyMs float64
	// This is telemetry for which container logs were latent (max over a period of time)
	AgentLogProcessingMaxLatencyMsContainer string
	// CommonProperties indicates the dimensions that are sent with every event/metric
	CommonProperties map[string]string
	// TelemetryClient is the client used to send the telemetry
	TelemetryClient appinsights.TelemetryClient
	// ContainerLogTelemetryTicker sends telemetry periodically
	ContainerLogTelemetryTicker *time.Ticker
	//Tracks the number of telegraf metrics sent successfully between telemetry ticker periods (uses ContainerLogTelemetryTicker)
	TelegrafMetricsSentCount float64
	//Tracks the number of send errors between telemetry ticker periods (uses ContainerLogTelemetryTicker)
	TelegrafMetricsSendErrorCount float64
)

const (
	clusterTypeACS                                    = "ACS"
	clusterTypeAKS                                    = "AKS"
	envAKSResourceID                                  = "AKS_RESOURCE_ID"
	envACSResourceName                                = "ACS_RESOURCE_NAME"
	envAppInsightsAuth                                = "APPLICATIONINSIGHTS_AUTH"
	envAppInsightsEndpoint                            = "APPLICATIONINSIGHTS_ENDPOINT"
	metricNameAvgFlushRate                            = "ContainerLogAvgRecordsFlushedPerSec"
	metricNameAvgLogGenerationRate                    = "ContainerLogsGeneratedPerSec"
	metricNameLogSize                                 = "ContainerLogsSize"
	metricNameAgentLogProcessingMaxLatencyMs          = "ContainerLogsAgentSideLatencyMs"
	metricNameNumberofTelegrafMetricsSentSuccessfully = "TelegrafMetricsSentCount"
	metricNameNumberofSendErrorsTelegrafMetrics       = "TelegrafMetricsSendErrorCount"

	defaultTelemetryPushIntervalSeconds = 300

	eventNameContainerLogInit   = "ContainerLogPluginInitialized"
	eventNameDaemonSetHeartbeat = "ContainerLogDaemonSetHeartbeatEvent"
)

// SendContainerLogPluginMetrics is a go-routine that flushes the data periodically (every 5 mins to App Insights)
func SendContainerLogPluginMetrics(telemetryPushIntervalProperty string) {
	telemetryPushInterval, err := strconv.Atoi(telemetryPushIntervalProperty)
	if err != nil {
		Log("Error Converting telemetryPushIntervalProperty %s. Using Default Interval... %d \n", telemetryPushIntervalProperty, defaultTelemetryPushIntervalSeconds)
		telemetryPushInterval = defaultTelemetryPushIntervalSeconds
	}

	ContainerLogTelemetryTicker = time.NewTicker(time.Second * time.Duration(telemetryPushInterval))

	start := time.Now()
	SendEvent(eventNameContainerLogInit, make(map[string]string))

	for ; true; <-ContainerLogTelemetryTicker.C {
		elapsed := time.Since(start)

		ContainerLogTelemetryMutex.Lock()
		flushRate := FlushedRecordsCount / FlushedRecordsTimeTaken * 1000
		logRate := FlushedRecordsCount / float64(elapsed/time.Second)
		logSizeRate := FlushedRecordsSize / float64(elapsed/time.Second)
		telegrafMetricsSentCount := TelegrafMetricsSentCount
		telegrafMetricsSendErrorCount := TelegrafMetricsSendErrorCount
		TelegrafMetricsSentCount = 0.0
		TelegrafMetricsSendErrorCount = 0.0
		FlushedRecordsCount = 0.0
		FlushedRecordsSize = 0.0
		FlushedRecordsTimeTaken = 0.0
		logLatencyMs := AgentLogProcessingMaxLatencyMs
		logLatencyMsContainer := AgentLogProcessingMaxLatencyMsContainer
		AgentLogProcessingMaxLatencyMs = 0
		AgentLogProcessingMaxLatencyMsContainer = ""
		ContainerLogTelemetryMutex.Unlock()

		if strings.Compare(strings.ToLower(os.Getenv("CONTROLLER_TYPE")), "daemonset") == 0 {
			SendEvent(eventNameDaemonSetHeartbeat, make(map[string]string))
			flushRateMetric := appinsights.NewMetricTelemetry(metricNameAvgFlushRate, flushRate)
			TelemetryClient.Track(flushRateMetric)
			logRateMetric := appinsights.NewMetricTelemetry(metricNameAvgLogGenerationRate, logRate)
			logSizeMetric := appinsights.NewMetricTelemetry(metricNameLogSize, logSizeRate)
			TelemetryClient.Track(logRateMetric)
			Log("Log Size Rate: %f\n", logSizeRate)
			TelemetryClient.Track(logSizeMetric)
			logLatencyMetric := appinsights.NewMetricTelemetry(metricNameAgentLogProcessingMaxLatencyMs, logLatencyMs)
			logLatencyMetric.Properties["Container"] = logLatencyMsContainer
			TelemetryClient.Track(logLatencyMetric)
		}
		TelemetryClient.Track(appinsights.NewMetricTelemetry(metricNameNumberofTelegrafMetricsSentSuccessfully, telegrafMetricsSentCount))
		TelemetryClient.Track(appinsights.NewMetricTelemetry(metricNameNumberofSendErrorsTelegrafMetrics, telegrafMetricsSendErrorCount))
		start = time.Now()
	}
}

// SendEvent sends an event to App Insights
func SendEvent(eventName string, dimensions map[string]string) {
	Log("Sending Event : %s\n", eventName)
	event := appinsights.NewEventTelemetry(eventName)

	// add any extra Properties
	for k, v := range dimensions {
		event.Properties[k] = v
	}

	TelemetryClient.Track(event)
}

// SendException  send an event to the configured app insights instance
func SendException(err interface{}) {
	if TelemetryClient != nil {
		TelemetryClient.TrackException(err)
	}
}

// InitializeTelemetryClient sets up the telemetry client to send telemetry to the App Insights instance
func InitializeTelemetryClient(agentVersion string) (int, error) {
	encodedIkey := os.Getenv(envAppInsightsAuth)
	if encodedIkey == "" {
		Log("Environment Variable Missing \n")
		return -1, errors.New("Missing Environment Variable")
	}

	decIkey, err := base64.StdEncoding.DecodeString(encodedIkey)
	if err != nil {
		Log("Decoding Error %s", err.Error())
		return -1, err
	}

	appInsightsEndpoint := os.Getenv(envAppInsightsEndpoint)
	telemetryClientConfig := appinsights.NewTelemetryConfiguration(string(decIkey))
	// endpoint override required only for sovereign clouds
	if appInsightsEndpoint != "" {
		Log("Overriding the default AppInsights EndpointUrl with %s", appInsightsEndpoint)
		telemetryClientConfig.EndpointUrl = envAppInsightsEndpoint
	}
	TelemetryClient = appinsights.NewTelemetryClientFromConfig(telemetryClientConfig)

	telemetryOffSwitch := os.Getenv("DISABLE_TELEMETRY")
	if strings.Compare(strings.ToLower(telemetryOffSwitch), "true") == 0 {
		Log("Appinsights telemetry is disabled \n")
		TelemetryClient.SetIsEnabled(false)
	}

	CommonProperties = make(map[string]string)
	CommonProperties["Computer"] = os.Getenv("CI_HOSTNAME")
	CommonProperties["WorkspaceID"] = os.Getenv("CI_WSID")
	CommonProperties["ControllerType"] = os.Getenv("CONTROLLER_TYPE")
	CommonProperties["AgentVersion"] = agentVersion

	aksResourceID := os.Getenv(envAKSResourceID)
	// if the aks resource id is not defined, it is most likely an ACS Cluster
	if aksResourceID == "" {
		CommonProperties["ACSResourceName"] = os.Getenv(envACSResourceName)
		CommonProperties["ClusterType"] = clusterTypeACS

		CommonProperties["SubscriptionID"] = ""
		CommonProperties["ResourceGroupName"] = ""
		CommonProperties["ClusterName"] = ""
		CommonProperties["Region"] = ""
		CommonProperties["AKS_RESOURCE_ID"] = ""

	} else {
		CommonProperties["ACSResourceName"] = ""
		CommonProperties["AKS_RESOURCE_ID"] = aksResourceID
		splitStrings := strings.Split(aksResourceID, "/")
		if len(splitStrings) > 0 && len(splitStrings) < 10 {
			CommonProperties["SubscriptionID"] = splitStrings[2]
			CommonProperties["ResourceGroupName"] = splitStrings[4]
			CommonProperties["ClusterName"] = splitStrings[8]
		}
		CommonProperties["ClusterType"] = clusterTypeAKS

		region := os.Getenv("AKS_REGION")
		CommonProperties["Region"] = region
	}

	TelemetryClient.Context().CommonProperties = CommonProperties
	return 0, nil
}

// PushToAppInsightsTraces sends the log lines as trace messages to the configured App Insights Instance
func PushToAppInsightsTraces(records []map[interface{}]interface{}, severityLevel contracts.SeverityLevel, tag string) int {
	var logLines []string
	for _, record := range records {
		// If record contains config error or prometheus scraping errors send it to KubeMonAgentEvents table
		var logEntry = ToString(record["log"])
		// if strings.Contains(logEntry, "config::error") {
		// 	populateKubeMonAgentEventHash(record, ConfigError)
		// } else if strings.Contains(logEntry, "E! [inputs.prometheus]") {
		// 	populateKubeMonAgentEventHash(record, PromScrapingError)
		// } else {
			logLines = append(logLines, logEntry)
		// }
	}

	traceEntry := strings.Join(logLines, "\n")
	traceTelemetryItem := appinsights.NewTraceTelemetry(traceEntry, severityLevel)
	traceTelemetryItem.Properties["tag"] = tag
	TelemetryClient.Track(traceTelemetryItem)
	return output.FLB_OK
}
