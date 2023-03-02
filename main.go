package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/log"
	"github.com/optionfactory/legopfa/certmanager"
	"github.com/optionfactory/legopfa/dnsupdaters"
	"github.com/optionfactory/legopfa/httpserverhandlers"
)

var version string

func main() {
	thisExecutable, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot get executable: %v", err)
	}
	thisExecutableName := filepath.Base(thisExecutable)
	log.Infof("%s version %s", thisExecutableName, version)
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <configuration_path>", thisExecutableName)
	}
	configuration, err := loadJson[certmanager.Configuration](os.Args[1])
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	cm, err := certmanager.MakeCertManager(configuration)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	httpServerHandler, err := httpserverhandlers.ByName(configuration.HttpServerHandler)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	isHttpServerRunning := httpServerHandler.IsRunning()
	log.Infof("http server is running: %v", isHttpServerRunning)
	if !isHttpServerRunning && len(configuration.DnsRecordsToUpdate) > 0 {
		log.Infof("updating dns records: %v", configuration.DnsRecordsToUpdate)
		err = dnsupdaters.FromConfiguration(configuration).Update()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		log.Infof("dns records updated")
	}
	needsCreationOrRenewal, daysUntilExpiration, err := cm.NeedsCreationOrRenewal()
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if !needsCreationOrRenewal {
		log.Infof("certificate expires in %d days, threshold is 30 days: no renewal.", daysUntilExpiration)
		log.Infof("done.")
		return
	}
	account, err := cm.CreateAccount()
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	client, err := cm.CreateClient(account, isHttpServerRunning)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	err = cm.CreateOrRenewCertificate(client)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Infof("certificate renewed")
	if httpServerHandler.IsRunning() {
		log.Infof("reloading %s", httpServerHandler.ServerName())
		err = httpServerHandler.ReloadConfiguration()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}
	log.Infof("done.")
}

func loadJson[K any](path string) (*K, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Could not deserialize %s: %v", path, err)
	}
	defer file.Close()
	var deserialized K
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&deserialized)
	if err != nil {
		return nil, fmt.Errorf("Could not deserialize %s: %v", path, err)
	}
	return &deserialized, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
