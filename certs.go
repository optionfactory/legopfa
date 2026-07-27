package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/gandiv5"
	"github.com/go-acme/lego/v5/providers/dns/route53"
	"github.com/go-acme/lego/v5/registration"
)

type Configuration struct {
	KeyType              certcrypto.KeyType `json:"key_type"`
	Email                string             `json:"email"`
	Domains              []string           `json:"domains"`
	ProviderType         string             `json:"provider_type"`
	HttpServerHandler    string             `json:"http_server_handler"`
	HttpUpstreamBindPort string             `json:"http_upstream_bind_port"`
	DnsClientId          string             `json:"dns_client_id"`
	DnsClientSecret      string             `json:"dns_client_secret"`
	DnsRegion            string             `json:"dns_region"`
	DnsHostedZoneId      string             `json:"dns_hosted_zone_id"`
	StoragePath          string             `json:"storage_path"`
	AcmeDirectoryUrl     string             `json:"acme_directory_url"`
	DnsResolvers         []string           `json:"dns_resolvers"`
}

type LegoAccount struct {
	email            string
	registrationInfo *acme.ExtendedAccount
	key              crypto.Signer
}

func (self *LegoAccount) GetEmail() string {
	return self.email
}

func (self *LegoAccount) GetRegistration() *acme.ExtendedAccount {
	return self.registrationInfo
}

func (self *LegoAccount) GetPrivateKey() crypto.Signer {
	return self.key
}

type CertManager struct {
	Configuration *Configuration
}

const useragent string = "legopfa"

func MakeCertManager(conf *Configuration) (*CertManager, error) {
	supportedKeyTypes := []certcrypto.KeyType{
		certcrypto.EC256,
		certcrypto.EC384,
		certcrypto.RSA2048,
		certcrypto.RSA3072,
		certcrypto.RSA4096,
		certcrypto.RSA8192,
	}
	supportedProviders := []string{
		"http",
		"http_reverse_proxy",
		"gandi",
		"cloudflare",
		"route53",
	}
	supportedHttpServerHandlers := []string{
		"",
		"none",
		"nginx",
	}

	if !slices.Contains(supportedKeyTypes, certcrypto.KeyType(conf.KeyType)) {
		return nil, fmt.Errorf("invalid key_type in configuration: expected one of: %v, got '%s'", supportedKeyTypes, conf.KeyType)
	}
	if !slices.Contains(supportedProviders, string(conf.ProviderType)) {
		return nil, fmt.Errorf("invalid provider_type in configuration: expected one of: %v, got '%s'", supportedProviders, conf.ProviderType)
	}
	if !slices.Contains(supportedHttpServerHandlers, conf.HttpServerHandler) {
		return nil, fmt.Errorf("invalid http_server_handler in configuration: expected one of: %v, got '%s'", supportedHttpServerHandlers, conf.HttpServerHandler)
	}
	if conf.HttpServerHandler == "" {
		conf.HttpServerHandler = "none"
	}
	if conf.StoragePath == "" {
		return nil, fmt.Errorf("storage_path must be configured")
	}
	if len(conf.Domains) == 0 {
		return nil, fmt.Errorf("domains must be a non empty array")
	}
	if conf.Email == "" {
		return nil, fmt.Errorf("email must be configured")
	}
	if conf.ProviderType == "http_reverse_proxy" && conf.HttpServerHandler == "none" {
		return nil, fmt.Errorf("http_server_handler must be provided when using the http_reverse_proxy provider_type")
	}
	if conf.HttpUpstreamBindPort != "" {
		portInt, err := strconv.Atoi(conf.HttpUpstreamBindPort)
		if err != nil || portInt < 1 || portInt > 65535 {
			return nil, fmt.Errorf("invalid http_upstream_bind_port: must be a valid port number between 1 and 65535")
		}
	}

	if conf.DnsClientSecret != "" {
		s, err := source(conf.DnsClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve dns_client_secret: %w", err)
		}
		conf.DnsClientSecret = s
	}
	if conf.DnsClientId != "" {
		s, err := source(conf.DnsClientId)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve dns_client_id: %w", err)
		}
		conf.DnsClientId = s
	}

	switch conf.ProviderType {
	case "cloudflare":
		if conf.DnsClientSecret == "" {
			return nil, fmt.Errorf("dns_client_secret must be provided when using the cloudflare provider_type (containing the CLOUDFLARE_DNS_API_TOKEN)")
		}
	case "gandi":
		if conf.DnsClientSecret == "" {
			return nil, fmt.Errorf("dns_client_secret must be provided when using the gandi provider_type (containing the personal access token)")
		}
	case "route53":
		if conf.DnsClientId == "" {
			return nil, fmt.Errorf("dns_client_id must be provided when using the route53 provider_type")
		}
		if conf.DnsClientSecret == "" {
			return nil, fmt.Errorf("dns_client_secret must be provided when using the route53 provider_type")
		}
		if conf.DnsRegion == "" {
			return nil, fmt.Errorf("dns_region must be provided when using the route53 provider_type")
		}
	}

	if conf.AcmeDirectoryUrl == "" {
		conf.AcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory"
	}

	return &CertManager{Configuration: conf}, nil
}

func (self *CertManager) CreateAccount() (*LegoAccount, error) {
	key, err := certcrypto.GeneratePrivateKey(self.Configuration.KeyType)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	coreApi, err := api.New(httpClient, useragent, self.Configuration.AcmeDirectoryUrl, "", key)
	if err != nil {
		return nil, fmt.Errorf("Could not complete registration: %w", err)
	}
	accountWithoutRegistration := &LegoAccount{
		email: self.Configuration.Email,
		key:   key,
	}

	regClient := registration.NewRegistrar(coreApi, accountWithoutRegistration)
	reg, err := regClient.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("Could not complete registration: %w", err)
	}
	return &LegoAccount{
		email:            self.Configuration.Email,
		registrationInfo: reg,
		key:              key,
	}, nil
}

func (self *CertManager) UsesReverseProxy() bool {
	return self.Configuration.ProviderType == "http_reverse_proxy"
}

func (self *CertManager) CreateClient(account *LegoAccount, reverseProxyIsRunning bool) (*lego.Client, error) {
	config := lego.NewConfig(account)
	config.Certificate = lego.CertificateConfig{
		Timeout: time.Duration(30) * time.Second,
	}
	config.UserAgent = useragent
	config.HTTPClient.Timeout = time.Duration(30) * time.Second
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Could not create client: %v", err)
	}

	if self.Configuration.ProviderType == "http" || self.Configuration.ProviderType == "http_reverse_proxy" {
		port := "80"
		bindAsUpstream := reverseProxyIsRunning && self.Configuration.ProviderType == "http_reverse_proxy"
		if bindAsUpstream {
			if self.Configuration.HttpUpstreamBindPort != "" {
				port = self.Configuration.HttpUpstreamBindPort
			} else {
				port = "8888"
			}
		}
		srv := http01.NewProviderServer("", port)
		err := client.Challenge.SetHTTP01Provider(srv)
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	if self.Configuration.ProviderType == "cloudflare" {

		opts := &dns01.Options{RecursiveNameservers: self.Configuration.DnsResolvers}
		dns01.SetDefaultClient(dns01.NewClient(opts))

		cloudConfig := cloudflare.NewDefaultConfig()
		cloudConfig.AuthToken = self.Configuration.DnsClientSecret

		provider, err := cloudflare.NewDNSProviderConfig(cloudConfig)
		if err != nil {
			return nil, err
		}
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, err
		}
		return client, nil
	}
	if self.Configuration.ProviderType == "route53" {
		opts := &dns01.Options{RecursiveNameservers: self.Configuration.DnsResolvers}
		dns01.SetDefaultClient(dns01.NewClient(opts))

		route53Config := route53.NewDefaultConfig()
		route53Config.AccessKeyID = self.Configuration.DnsClientId
		route53Config.SecretAccessKey = self.Configuration.DnsClientSecret
		route53Config.Region = self.Configuration.DnsRegion
		if self.Configuration.DnsHostedZoneId != "" {
			route53Config.HostedZoneID = self.Configuration.DnsHostedZoneId
		}

		provider, err := route53.NewDNSProviderConfig(route53Config)
		if err != nil {
			return nil, err
		}
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, err
		}
		return client, nil
	}
	if self.Configuration.ProviderType == "gandi" {
		opts := &dns01.Options{RecursiveNameservers: self.Configuration.DnsResolvers}
		dns01.SetDefaultClient(dns01.NewClient(opts))

		gandiConfig := gandiv5.NewDefaultConfig()
		gandiConfig.PersonalAccessToken = self.Configuration.DnsClientSecret
		provider, err := gandiv5.NewDNSProviderConfig(gandiConfig)
		if err != nil {
			return nil, err
		}
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, err
		}
		return client, nil
	}
	return nil, fmt.Errorf("Unsupported provider type: '%s'", self.Configuration.ProviderType)
}

func (self *CertManager) NeedsCreationOrRenewal() (bool, int, error) {
	oldCert, err := loadCertificate(self.Configuration.StoragePath)
	if err != nil {
		return false, 0, err
	}
	if oldCert != nil {
		oldCertDomains := certcrypto.ExtractDomains(oldCert)
		sameDomains := domainsMatch(oldCertDomains, self.Configuration.Domains)
		daysUntilExpiration := int(time.Until(oldCert.NotAfter).Hours() / 24.0)
		if sameDomains && daysUntilExpiration > 30 {
			return false, daysUntilExpiration, nil
		}
	}
	return true, 0, nil
}

func (self *CertManager) CreateOrRenewCertificate(client *lego.Client) error {
	if len(self.Configuration.Domains) == 0 {
		return fmt.Errorf("no domains configured for certificate creation")
	}
	request := certificate.ObtainRequest{
		Domains:                        self.Configuration.Domains,
		Bundle:                         true,
		KeyType:                        self.Configuration.KeyType,
		MustStaple:                     false,
		PreferredChain:                 "",
		AlwaysDeactivateAuthorizations: false,
	}
	cert, err := client.Certificate.Obtain(context.Background(), request)
	if err != nil {
		return fmt.Errorf("Could not obtain certificates: %w", err)
	}
	err = saveCertificates(self.Configuration.StoragePath, cert, self.Configuration.Domains[0])
	if err != nil {
		return fmt.Errorf("Error saving certificates: %w", err)
	}
	return nil
}

func domainsMatch(configDomains []string, certDomains []string) bool {
	if len(configDomains) != len(certDomains) {
		return false
	}
	configCopy := slices.Clone(configDomains)
	certCopy := slices.Clone(certDomains)
	slices.Sort(configCopy)
	slices.Sort(certCopy)
	return slices.Equal(configCopy, certCopy)
}

const certFilesPerm = 0o600

func loadCertificate(basePath string) (*x509.Certificate, error) {
	fp := filepath.Join(basePath, "server.crt")
	_, err := os.Stat(fp)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	certificates, err := certcrypto.ParsePEMBundle(bytes)
	if err != nil {
		return nil, err
	}
	return certificates[0], nil
}

func saveCertificates(basePath string, cert *certificate.Resource, domain string) error {
	cleanBase := filepath.Clean(basePath)
	crtPath := filepath.Join(cleanBase, "server.crt")
	keyPath := filepath.Join(cleanBase, "server.key")
	crtTmpPath := crtPath + ".tmp"
	keyTmpPath := keyPath + ".tmp"

	if err := os.WriteFile(crtTmpPath, cert.Certificate, certFilesPerm); err != nil {
		return fmt.Errorf("Unable to save server.crt for domain %s: %w", domain, err)
	}
	if err := os.Rename(crtTmpPath, crtPath); err != nil {
		return fmt.Errorf("Unable to commit server.crt for domain %s: %w", domain, err)
	}

	if err := os.WriteFile(keyTmpPath, cert.PrivateKey, certFilesPerm); err != nil {
		return fmt.Errorf("Unable to save server.key for domain %s: %w", domain, err)
	}
	if err := os.Rename(keyTmpPath, keyPath); err != nil {
		return fmt.Errorf("Unable to commit server.key for domain %s: %w", domain, err)
	}

	return nil
}

func source(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "env:") {
		envVar := strings.TrimPrefix(value, "env:")
		val := os.Getenv(envVar)
		if val == "" {
			return "", fmt.Errorf("environment variable %q is empty or not set", envVar)
		}
		return strings.TrimSpace(val), nil
	}
	if strings.HasPrefix(value, "secret:") {
		secretName := strings.TrimPrefix(value, "secret:")
		root, err := os.OpenRoot("/run/secrets")
		if err != nil {
			return "", fmt.Errorf("failed to open secret directory: %w", err)
		}
		defer root.Close()
		content, err := root.ReadFile(secretName)
		if err != nil {
			return "", fmt.Errorf("failed to read container secret %q: %w", secretName, err)
		}

		return strings.TrimSpace(string(content)), nil
	}
	return value, nil
}
