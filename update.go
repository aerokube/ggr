package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	
	. "github.com/aerokube/ggr/config"	
)

func handleNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var requestData struct {
		User string `json:"user"`
	}
	if err := json.Unmarshal(body, &requestData); err != nil {
		http.Error(w, "Failed to unmarshal JSON request", http.StatusBadRequest)
		return
	}
	fmt.Println("Received notification for user:", requestData.User)
	// Extract IP address and port from the request
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to extract IP address and port", http.StatusInternalServerError)
		return
	}
	port := strconv.Itoa(r.RemoteAddr)
	fmt.Println("Caller IP:", ip)
	fmt.Println("Caller Port:", port)
	
	// Update XML file
	filename := requestData.User + ".xml" // Replace with the actual XML filename
	newHost := ip
	newPort := port
	newCount := "1"

	fmt.Println("Updating XML file for user:", requestData.User)
	err = updateXMLFiles(quotaDir, filename, newHost, newPort, newCount)
	if err != nil {
		http.Error(w, "Failed to update XML file", http.StatusInternalServerError)
		return
	}
  	// reload quotas
	err := loadQuotaFiles(quotaDir)
	if err != nil {
		log.Printf("[-] [-] [INIT] [-] [-] [-] [-] [-] [-] [%v]\n", err)
	}

	response := map[string]bool{"success": true}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func updateXMLFiles(quotaDir, filename, newHost, newPort, newCount string) error {
	filePath := filepath.Join(quotaDir, filename)

	xmlContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read XML file '%s': %v", filename, err)
	}

	var browsers Browsers
	if err := xml.Unmarshal(xmlContent, &browsers); err != nil {
		return fmt.Errorf("failed to unmarshal XML file '%s': %v", filename, err)
	}

	for i := range browsers.Browser {
		browser := &browsers.Browser[i]
		for j := range browser.Version.Region {
			region := &browser.Version.Region[j]
			for k := range region.Host {
				host := &region.Host[k]
				host.Name = newHost
				host.Port = newPort
				host.Count = newCount
			}
		}
	}

	updatedXMLContent, err := xml.MarshalIndent(browsers, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated XML file '%s': %v", filename, err)
	}

	if err := ioutil.WriteFile(filePath, updatedXMLContent, 0644); err != nil {
		return fmt.Errorf("failed to write updated XML file '%s': %v", filename, err)
	}

	fmt.Printf("XML file '%s' updated successfully\n", filename)

	return nil
}
