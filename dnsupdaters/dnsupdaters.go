package dnsupdaters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/optionfactory/legopfa/certmanager"
	"io"
	"net"
	"net/http"
	"time"
)

type DnsUpdater interface {
	Update() error
}

func FromConfiguration(conf *certmanager.Configuration) DnsUpdater {
	if conf.ProviderType != "gandi" && conf.ProviderType != "route53" {
		return &NullDnsUpdater{}
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

	if conf.ProviderType == "gandi" {
		return &GandiDnsUpdater{
			HttpClient:   httpClient,
			ClientSecret: conf.DnsClientSecret,
			Records:      conf.DnsRecordsToUpdate,
		}

	}
	return &Route53DnsUpdater{
		HttpClient:   httpClient,
		ClientId:     conf.DnsClientId,
		ClientSecret: conf.DnsClientSecret,
		Region:       conf.DnsRegion,
		Records:      conf.DnsRecordsToUpdate,
	}
}

type NullDnsUpdater struct {
}

func (self *NullDnsUpdater) Update() error {
	return nil
}

type GandiDnsUpdater struct {
	HttpClient   *http.Client
	ClientSecret string
	Records      []certmanager.DnsRecord
}

type GandiDnsRecordUpdateRequest struct {
	Ttl    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

func (self *GandiDnsUpdater) Update() error {
	ip, err := myPublicIp(self.HttpClient)
	if err != nil {
		return err
	}
	req := &GandiDnsRecordUpdateRequest{
		Ttl:    300,
		Values: []string{ip},
	}
	json, err := json.Marshal(req)
	if err != nil {
		return err
	}
	for _, record := range self.Records {
		url := fmt.Sprintf("https://dns.api.gandi.net/api/v5/domains/%s/records/%s/A", record.Domain, record.Name)
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(json))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Api-Key", self.ClientSecret)
		_, err = self.HttpClient.Do(req)
		if err != nil {
			return err
		}
	}
	return nil
}

type Route53DnsUpdater struct {
	HttpClient   *http.Client
	ClientId     string
	ClientSecret string
	Region       string
	Records      []certmanager.DnsRecord
}

func (self *Route53DnsUpdater) Update() error {
	return fmt.Errorf("Route53DnsUpdater is not supported yet")
}

func myPublicIp(httpClient *http.Client) (string, error) {
	resp, err := httpClient.Get("https://ifconfig.me/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}
