package ipreport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type IpAddrReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
			AsOwner    string `json:"as_owner"`
			Network    string `json:"network"`
			Asn        int    `json:"asn"`
			Country    string `json:"country"`
			Reputation int    `json:"reputation"`
			Tags       []any  `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetIpReport fetches an IP address report
func GetIpReport(ipaddr string) (IpAddrReport, error) {
	var ip IpAddrReport
	if ipaddr == "" {
		return ip, fmt.Errorf("ip address cannot be empty")
	}

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return ip, fmt.Errorf("VT_API_KEY is not set")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ipaddr)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return IpAddrReport{}, fmt.Errorf("failed creating request: %w", err)
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{Timeout: 8 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return ip, fmt.Errorf("client request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var e vtAPIError
		if err := json.NewDecoder(res.Body).Decode(&e); err == nil && e.Error.Code != "" {
			return ip, fmt.Errorf("IP report API returned %d: %s - %s", res.StatusCode, e.Error.Code, e.Error.Message)
		}
		return ip, fmt.Errorf("IP report API returned %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(&ip); err != nil {
		return ip, fmt.Errorf("decode failed: %w", err)
	}
	return ip, nil
}

// ---------------------------------------------------

// Fetch recent domain resolutions for the IP.
type Resolution struct {
	Data []struct {
		Attributes struct {
			HostName string `json:"host_name"`
			Date     int64  `json:"date"`
			Stats    struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
			} `json:"host_name_last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func getIPResolutions(ipaddr string, limit int) (Resolution, error) {
	var out Resolution
	if ipaddr == "" {
		return out, fmt.Errorf("ip address cannot be empty")
	}
	if limit <= 0 {
		limit = 3
	}

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, fmt.Errorf("VT_API_KEY is not set")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s/resolutions?limit=%d", ipaddr, limit)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return out, fmt.Errorf("failed creating resolution request: %w", err)
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{Timeout: 8 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("resolution request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var e vtAPIError
		if err := json.NewDecoder(res.Body).Decode(&e); err == nil && e.Error.Code != "" {
			return out, fmt.Errorf("resolution API returned %d: %s - %s", res.StatusCode, e.Error.Code, e.Error.Message)
		}
		return out, fmt.Errorf("resolution API returned %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("resolution decode failed: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------

// Merged the view of both reports
type FinalReport struct {
	IP         string
	AsOwner    string
	ASN        int
	Country    string
	Reputation int
	Tags       []any
	Network    string
	Stats      struct {
		Malicious  int
		Suspicious int
		Undetected int
		Harmless   int
	}
	Resolutions []struct {
		HostName   string
		DateUnix   int64
		Malicious  int
		Suspicious int
	}
	Shodan struct {
		Ports     []int
		Vulns     []string
		HostNames []string
		Tags      []string
	}
}

// MergeReports combines the IP report and any associated domains into a single view.
func MergeReports(ipaddr string, limit int) (FinalReport, error) {
	var report FinalReport
	report.IP = ipaddr

	base, err := GetIpReport(ipaddr)
	if err != nil {
		return report, err
	}
	resolutions, err := getIPResolutions(ipaddr, limit)
	if err != nil {
		return report, err
	}

	attrs := base.Data.Attributes
	report.AsOwner = attrs.AsOwner
	report.ASN = attrs.Asn
	report.Network = attrs.Network
	report.Country = attrs.Country
	report.Reputation = attrs.Reputation
	report.Tags = attrs.Tags
	report.Stats.Malicious = attrs.LastAnalysisStats.Malicious
	report.Stats.Suspicious = attrs.LastAnalysisStats.Suspicious
	report.Stats.Undetected = attrs.LastAnalysisStats.Undetected
	report.Stats.Harmless = attrs.LastAnalysisStats.Harmless

	for _, v := range resolutions.Data {
		report.Resolutions = append(report.Resolutions, struct {
			HostName   string
			DateUnix   int64
			Malicious  int
			Suspicious int
		}{
			HostName:   v.Attributes.HostName,
			DateUnix:   v.Attributes.Date,
			Malicious:  v.Attributes.Stats.Malicious,
			Suspicious: v.Attributes.Stats.Suspicious,
		})
	}

	return report, nil
}

// ---------------------------------------------------

type vtAPIError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
