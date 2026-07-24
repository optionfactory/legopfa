package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v5/log"
)

var version string

func main() {
	thisExecutable, err := os.Executable()
	if err != nil {
		log.Fatal("cannot get executable", slog.Any("error", err))
	}
	thisExecutableName := filepath.Base(thisExecutable)
	log.Info("starting application", slog.String("executable", thisExecutableName), slog.String("version", version))

	if len(os.Args) != 2 {
		log.Fatal("invalid usage", slog.String("usage", fmt.Sprintf("%s <configuration_path>", thisExecutableName)))
	}

	configuration, err := loadJson[Configuration](os.Args[1])
	if err != nil {
		log.Fatal("failed to load configuration", slog.Any("error", err))
	}
	if len(configuration.Domains) == 0 {
		log.Info("no domains found in configuration")
		log.Info("done")
		return
	}

	cm, err := MakeCertManager(configuration)
	if err != nil {
		log.Fatal("failed to create cert manager", slog.Any("error", err))
	}

	httpServerHandler, err := MakeServerHandler(configuration.HttpServerHandler)
	if err != nil {
		log.Fatal("failed to create server handler", slog.Any("error", err))
	}

	needsCreationOrRenewal, daysUntilExpiration, err := cm.NeedsCreationOrRenewal()
	if err != nil {
		log.Fatal("failed to check certificate status", slog.Any("error", err))
	}
	if !needsCreationOrRenewal {
		log.Info("no renewal required", slog.Int("days_until_expiration", daysUntilExpiration), slog.Int("threshold_days", 30))
		log.Info("done")
		return
	}

	isHttpServerRunning := false
	if cm.UsesReverseProxy() {
		isHttpServerRunning = httpServerHandler.IsRunning()
		log.Info("checked reverse proxy status", slog.Bool("running", isHttpServerRunning))
	}

	account, err := cm.CreateAccount()
	if err != nil {
		log.Fatal("failed to create ACME account", slog.Any("error", err))
	}

	client, err := cm.CreateClient(account, isHttpServerRunning)
	if err != nil {
		log.Fatal("failed to create ACME client", slog.Any("error", err))
	}

	err = cm.CreateOrRenewCertificate(client)
	if err != nil {
		log.Fatal("failed to obtain or renew certificate", slog.Any("error", err))
	}
	log.Info("certificate renewed successfully")

	if httpServerHandler.IsRunning() {
		log.Info("reloading web server", slog.String("server", httpServerHandler.ServerName()))
		err = httpServerHandler.ReloadConfiguration()
		if err != nil {
			log.Fatal("failed to reload web server configuration", slog.Any("error", err))
		}
	}
	log.Info("done")
}

func loadJson[K any](path string) (*K, error) {
	cleanPath := filepath.Clean(path)
	b, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var config K
	if err := json.Unmarshal(b, &config); err != nil {
		return nil, fmt.Errorf("failed to deserialize %s: %w", path, err)
	}

	return &config, nil
}
