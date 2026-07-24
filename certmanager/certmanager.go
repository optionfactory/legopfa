package certmanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/gandiv5"
	"github.com/go-acme/lego/v5/providers/dns/route53"
	"github.com/go-acme/lego/v5/registration"
)

type DnsRecord struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

type Configuration struct {
	KeyType             certcrypto.KeyType `json:"key_type"`
	Email               string             `json:"email"`
	Domains             []string           `json:"domains"`
	ProviderType        string             `json:"provider_type"`
	HttpServerHandler   string             `json:"http_server_handler"`
	HttpUpstramBindPort string             `json:"http_upstream_bind_port"`
	DnsClientId         string             `json:"dns_client_id"`
	DnsClientSecret     string             `json:"dns_client_secret"`
	DnsRegion           string             `json:"dns_region"`
	DnsHostedZoneId     string             `json:"dns_hosted_zone_id"`
	DnsRecordsToUpdate  []DnsRecord        `json:"dns_records_to_update"`
	StoragePath         string             `json:"storage_path"`
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
	supportedKeyTypes := []string{
		"P256",
		"P384",
		"2048",
		"4096",
		"8192",
	}
	supportedProviders := []string{
		"http",
		"http_reverse_proxy",
		"gandi",
		"route53",
	}
	supportedHttpServerHandlers := []string{
		"none",
		"nginx",
	}
	if !contains(supportedKeyTypes, string(conf.KeyType)) {
		return nil, fmt.Errorf("invalid key_type in configuration: expected one of: %v, got '%s'", supportedKeyTypes, conf.KeyType)
	}
	if !contains(supportedProviders, string(conf.ProviderType)) {
		return nil, fmt.Errorf("invalid provider_type in configuration: expected one of: %v, got '%s'", supportedProviders, conf.ProviderType)
	}
	if !contains(supportedHttpServerHandlers, conf.HttpServerHandler) {
		return nil, fmt.Errorf("invalid http_server_handler in configuration: expected one of: %v, got '%s'", supportedHttpServerHandlers, conf.HttpServerHandler)
	}
	if conf.StoragePath == "" {
		return nil, fmt.Errorf("storage_path must be configured")
	}
	if len(conf.Domains) == 0 {
		return nil, fmt.Errorf("domains must be a non empty array")
	}
	if len(conf.DnsRecordsToUpdate) != 0 && conf.ProviderType != "gandi" && conf.ProviderType != "route53" {
		return nil, fmt.Errorf("dns_records can be configured only with dns providers")
	}
	if len(conf.DnsRecordsToUpdate) != 0 && conf.ProviderType != "route53" && conf.DnsHostedZoneId == "" {
		return nil, fmt.Errorf("dns_hosted_zone_id is required when dns_records_to_update is configured with route53")
	}
	if conf.Email == "" {
		return nil, fmt.Errorf("email must be configured")
	}
	if conf.ProviderType == "http_reverse_proxy" && conf.HttpServerHandler == "none" {
		return nil, fmt.Errorf("http_server_handler must be provided when using the http_reverse_proxy provider_type")
	}
	if conf.ProviderType == "gandi" {
		if conf.DnsClientSecret == "" {
			return nil, fmt.Errorf("dns_client_secret must be provided when using the gandi provider_type")
		}
	}
	if conf.ProviderType == "route53" {
		if conf.DnsClientId == "" {
			return nil, fmt.Errorf("dns_client_id must be provided when using the gandi provider_type")
		}
		if conf.DnsClientSecret == "" {
			return nil, fmt.Errorf("dns_client_secret must be provided when using the gandi provider_type")
		}
		if conf.DnsRegion == "" {
			return nil, fmt.Errorf("dns_region must be provided when using the gandi provider_type")
		}
	}
	cm := &CertManager{
		Configuration: conf,
	}
	return cm, nil
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

	coreApi, err := api.New(httpClient, useragent, "https://acme-v02.api.letsencrypt.org/directory", "", key.(crypto.Signer))
	if err != nil {
		return nil, fmt.Errorf("Could not complete registration: %v", err)
	}
	accountWithoutRegistration := &LegoAccount{
		email: self.Configuration.Email,
		key:   key.(crypto.Signer),
	}

	regClient := registration.NewRegistrar(coreApi, accountWithoutRegistration)
	reg, err := regClient.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("Could not complete registration: %v", err)
	}
	return &LegoAccount{
		email:            self.Configuration.Email,
		registrationInfo: reg,
		key:              key.(crypto.Signer),
	}, nil
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
			if self.Configuration.HttpUpstramBindPort != "" {
				port = self.Configuration.HttpUpstramBindPort
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
	if self.Configuration.ProviderType == "route53" {
		route53Config := &route53.Config{
			AccessKeyID:        self.Configuration.DnsClientId,
			SecretAccessKey:    self.Configuration.DnsClientSecret,
			SessionToken:       "",
			Region:             self.Configuration.DnsRegion,
			HostedZoneID:       "",
			MaxRetries:         5,
			AssumeRoleArn:      "",
			TTL:                10,
			PropagationTimeout: 2 * time.Minute,
			PollingInterval:    4 * time.Second,
			Client:             nil,
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
		gandiConfig := &gandiv5.Config{
			BaseURL:            "https://dns.api.gandi.net/api/v5",
			APIKey:             self.Configuration.DnsClientSecret,
			PropagationTimeout: 20 * time.Minute,
			PollingInterval:    20 * time.Second,
			HTTPClient: &http.Client{
				Timeout: 10 * time.Second,
			},
			TTL: 300,
		}
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
		sameDomains := stringSliceEquals(oldCertDomains, self.Configuration.Domains)
		daysUntilExpiration := int(time.Until(oldCert.NotAfter).Hours() / 24.0)
		if sameDomains && daysUntilExpiration > 30 {
			return false, daysUntilExpiration, nil
		}
	}
	return true, 0, nil
}

func (self *CertManager) CreateOrRenewCertificate(client *lego.Client) error {
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
		return fmt.Errorf("Could not obtain certificates: %v", err)
	}
	err = saveCertificates(self.Configuration.StoragePath, cert, self.Configuration.Domains[0])
	if err != nil {
		return fmt.Errorf("Error saving certificates: %v", err)
	}
	return nil
}

func stringSliceEquals(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func contains(hs []string, n string) bool {
	for _, v := range hs {
		if v == n {
			return true
		}
	}
	return false
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
	err := os.WriteFile(filepath.Join(basePath, "server.crt"), cert.Certificate, certFilesPerm)
	if err != nil {
		return fmt.Errorf("Unable to save server.crt for domain %s: %v", domain, err)
	}
	err = os.WriteFile(filepath.Join(basePath, "server.key"), cert.PrivateKey, certFilesPerm)
	if err != nil {
		return fmt.Errorf("Unable to save server.key for domain %s: %v", domain, err)
	}
	return nil
}
