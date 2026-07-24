package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var version string

func main() {
	thisExecutable, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot get executable: %v", err)
	}
	thisExecutableName := filepath.Base(thisExecutable)
	log.Printf("%s version %s", thisExecutableName, version)

	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <configuration_path>", thisExecutableName)
	}

	configuration, err := loadJson[Configuration](os.Args[1])
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if len(configuration.Domains) == 0 {
		log.Printf("no domains found in configuration.")
		log.Printf("done.")
		return
	}

	cm, err := MakeCertManager(configuration)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	httpServerHandler, err := MakeServerHandler(configuration.HttpServerHandler)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	needsCreationOrRenewal, daysUntilExpiration, err := cm.NeedsCreationOrRenewal()
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if !needsCreationOrRenewal {
		log.Printf("certificate expires in %d days, threshold is 30 days: no renewal.", daysUntilExpiration)
		log.Printf("done.")
		return
	}

	isHttpServerRunning := httpServerHandler.IsRunning()
	log.Printf("http server is running: %v", isHttpServerRunning)

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
	log.Printf("certificate renewed")

	if httpServerHandler.IsRunning() {
		log.Printf("reloading %s", httpServerHandler.ServerName())
		err = httpServerHandler.ReloadConfiguration()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}
	log.Printf("done.")
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
