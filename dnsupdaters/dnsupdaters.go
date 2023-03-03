package dnsupdaters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
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
	HostedZoneId string
	Records      []certmanager.DnsRecord
}

func (self *Route53DnsUpdater) Update() error {
	ip, err := myPublicIp(self.HttpClient)
	if err != nil {
		return err
	}
	config := &aws.Config{
		Credentials: credentials.NewStaticCredentials(self.ClientId, self.ClientSecret, ""),
		Region:      &self.Region,
	}
	session, err := session.NewSession(config)
	if err != nil {
		return err
	}
	route53Client := route53.New(session)
	for _, record := range self.Records {
		_, err := route53Client.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(self.HostedZoneId),
			ChangeBatch: &route53.ChangeBatch{
				Changes: []*route53.Change{{
					Action: aws.String("UPSERT"),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(fmt.Sprintf("%s.%s", record.Domain, record.Name)),
						Type: aws.String("A"),
						TTL:  aws.Int64(60),
						ResourceRecords: []*route53.ResourceRecord{{
							Value: aws.String(ip),
						}},
						//SetIdentifier:  aws.String("Arbitrary Id describing this change set"),
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
