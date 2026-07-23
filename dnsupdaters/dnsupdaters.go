package dnsupdaters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/optionfactory/legopfa/certmanager"
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
		HostedZoneId: conf.DnsHostedZoneId,
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
	reqBody := &GandiDnsRecordUpdateRequest{
		Ttl:    300,
		Values: []string{ip},
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	for _, record := range self.Records {
		url := fmt.Sprintf("https://dns.api.gandi.net/api/v5/domains/%s/records/%s/A", record.Domain, record.Name)
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(jsonBody))
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
	HostedZoneId string
	Records      []certmanager.DnsRecord
}

func (self *Route53DnsUpdater) Update() error {
	ip, err := myPublicIp(self.HttpClient)
	if err != nil {
		return err
	}

	// v2 replaces 'session' with a direct config object, and static credentials require the provider wrapper
	config := aws.Config{
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(self.ClientId, self.ClientSecret, "")),
		Region:      self.Region,
		HTTPClient:  self.HttpClient,
	}

	// Create the route53 client directly from the config
	route53Client := route53.NewFromConfig(config)

	for _, record := range self.Records {
		// API calls in v2 require a context.Context
		_, err := route53Client.ChangeResourceRecordSets(context.Background(), &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(self.HostedZoneId),
			ChangeBatch: &types.ChangeBatch{ // Sub-structs have moved to the types subpackage
				Changes: []types.Change{{
					Action: types.ChangeActionUpsert, // Use typed enums rather than raw strings
					ResourceRecordSet: &types.ResourceRecordSet{
						Name: aws.String(fmt.Sprintf("%s.%s", record.Domain, record.Name)),
						Type: types.RRTypeA,
						TTL:  aws.Int64(60),
						ResourceRecords: []types.ResourceRecord{{
							Value: aws.String(ip),
						}},
					},
				}},
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
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
