package main

import (
	"../include/fluent-bit-go/output"
)
import (
	"C"
	"encoding/json"
	"fmt"
	// "os"
	// "strings"
	"time"
	"unsafe"
	"bytes"
	"net/http"
	"log"
	"crypto/tls"
)

//export FLBPluginRegister
func FLBPluginRegister(ctx unsafe.Pointer) int {
	return output.FLBPluginRegister(ctx, "oms", "OMS GO!")
}

//export FLBPluginInit
// (fluentbit will call this)
// ctx (context) pointer to fluentbit context (state/ c code)
func FLBPluginInit(ctx unsafe.Pointer) int {
	// Log("Initializing out_oms go plugin for fluentbit")
	// agentVersion := os.Getenv("AGENT_VERSION")
	// if strings.Compare(strings.ToLower(os.Getenv("CONTROLLER_TYPE")), "replicaset") == 0 {
	// 	Log("Using %s for plugin config \n", ReplicaSetContainerLogPluginConfFilePath)
	// 	InitializePlugin(ReplicaSetContainerLogPluginConfFilePath, agentVersion)
	// } else {
	// 	Log("Using %s for plugin config \n", DaemonSetContainerLogPluginConfFilePath)
	// 	InitializePlugin(DaemonSetContainerLogPluginConfFilePath, agentVersion)
	// }
	// enableTelemetry := output.FLBPluginConfigKey(ctx, "EnableTelemetry")
	// if strings.Compare(strings.ToLower(enableTelemetry), "true") == 0 {
	// 	telemetryPushInterval := output.FLBPluginConfigKey(ctx, "TelemetryPushIntervalSeconds")
	// 	go SendContainerLogPluginMetrics(telemetryPushInterval)
	// } else {
	// 	Log("Telemetry is not enabled for the plugin %s \n", output.FLBPluginConfigKey(ctx, "Name"))
	// 	return output.FLB_OK
	// }
	//log.Printf("Hello cruel world")
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
	log.Printf("FLBPluginFlush is starting...")


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

	// incomingTag := strings.ToLower(C.GoString(tag))
	// if strings.Contains(incomingTag, "oms.container.log.flbplugin") {
	// 	// This will also include populating cache to be sent as for config events
	// 	return PushToAppInsightsTraces(records, appinsights.Information, incomingTag)
	// } else if strings.Contains(incomingTag, "oms.container.perf.telegraf") {
	// 	return PostTelegrafMetricsToLA(records)
	// }

	log.Printf("I'm calling PostDataHelper...")

	return PostDataHelper(records)
}


// FLBPluginExit exits the plugin
func FLBPluginExit() int {
	// ContainerLogTelemetryTicker.Stop()
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
		return "yolo"
	}
}

// CreateHTTPClient used to create the client for sending post requests to OMSEndpoint
func CreateHTTPClient() {
	cert, err := tls.LoadX509KeyPair("oms.crt", "oms.key")
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

	log.Printf("Successfully created HTTP Client")
}


// PostDataHelper sends data to the OMS endpoint
func PostDataHelper(tailPluginRecords []map[interface{}]interface{}) int {
	// start := time.Now()
	var dataItems []DataItem

	log.Printf("PostDataHelper starts")

	for _, record := range tailPluginRecords {
		log.Printf(ToString(record["log"]));
		containerID := "388b1a08956c78beab8cbaea5168d89a1e76c019d9ce53994bea50dff3457b0a"
		_ = "podname"
		logEntrySource := ToString(record["stream"]);

		stringMap := make(map[string]string)

		stringMap["LogEntry"] = ToString(record["log"])
		stringMap["LogEntrySource"] = logEntrySource
		stringMap["LogEntryTimeStamp"] = ToString(record["time"])
		stringMap["SourceSystem"] = "Containers"
		stringMap["Id"] = containerID
		stringMap["Image"] = "bragi92/test"
		stringMap["Name"] = "kaveeshwindows"

		var dataItem DataItem
		dataItem = DataItem{
			ID:                    stringMap["Id"],
			LogEntry:              stringMap["LogEntry"],
			LogEntrySource:        stringMap["LogEntrySource"],
			LogEntryTimeStamp:     stringMap["LogEntryTimeStamp"],
			LogEntryTimeOfCommand: stringMap["LogEntryTimeStamp"],
			SourceSystem:          stringMap["SourceSystem"],
			Computer:              "kaveeshwindowsdesktop",
			Image:                 stringMap["Image"],
			Name:                  stringMap["Name"],
		
		}

		e, err := json.Marshal(dataItem)
    	if err != nil {
      		fmt.Println(err)
   		}

    	fmt.Println(string(e))
			dataItems = append(dataItems, dataItem)
		}

	if len(dataItems) > 0 {
		logEntry := ContainerLogBlob{
			DataType:  ContainerLogDataType,
			IPName:    IPName,
			DataItems: dataItems}

		marshalled, err := json.Marshal(logEntry)
		if err != nil {
			// message := fmt.Sprintf("Error while Marshalling log Entry: %s", err.Error())
			// Log(message)
			// SendException(message)
			return output.FLB_OK
		}
		// /subscriptions/692aea0b-2d89-4e7e-ae30-fffe40782ee2/resourceGroups/rashmi-1-17-test/providers/Microsoft.OperationalInsights/workspaces/rashmi-1-17-test
		OMSEndpoint := "https://82b419ad-6b6c-4a03-a1eb-34b05c8da3ee.ods.opinsights.azure.com/OperationalData.svc/PostJsonDataItems"

		req, _ := http.NewRequest("POST", OMSEndpoint, bytes.NewBuffer(marshalled))

		req.Header.Set("Content-Type", "application/json")
		// expensive to do string len for every request, so use a flag
		// if ResourceCentric == true {
		// 	req.Header.Set("x-ms-AzureResourceId", ResourceID)
		// }

		log.Printf("Sending HTTP Request")

		resp, err := HTTPClient.Do(req)

		if err != nil {
			// message := fmt.Sprintf("Error when sending request %s \n", err.Error())
			// Log(message)
			// // Commenting this out for now. TODO - Add better telemetry for ods errors using aggregation
			// //SendException(message)
			// Log("Failed to flush %d records after %s", len(dataItems), elapsed)
			log.Printf("%s \n", err.Error())
			return output.FLB_RETRY
		}

		if resp == nil || resp.StatusCode != 200 {
			if resp != nil {
				log.Printf("Status %s Status Code %d", resp.Status, resp.StatusCode)
			}
			return output.FLB_RETRY
		}

		log.Printf("Status code == %s", resp.StatusCode)

		log.Printf("Closing http")

		defer resp.Body.Close()

		log.Printf("Successfully flushed...")
		// Log("PostDataHelper::Info::Successfully flushed %d records in %s", numRecords, elapsed)
	
	}

	return output.FLB_OK
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