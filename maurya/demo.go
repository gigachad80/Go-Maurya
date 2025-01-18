package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// VirusTotalResponse represents the complete response structure from VirusTotal API
type VirusTotalResponse struct {
	BitDefenderInfo                string            `json:"BitDefender domain info"`
	DetectedCommunicatingSamples   []DetectedSample  `json:"detected_communicating_samples"`
	DetectedDownloadedSamples      []DetectedSample  `json:"detected_downloaded_samples"`
	DetectedReferrerSamples        []DetectedSample  `json:"detected_referrer_samples"`
	ResponseCode                   int               `json:"response_code"`
	VerboseMsg                     string            `json:"verbose_msg"`
	Whois                          string            `json:"whois,omitempty"`
	Categories                     map[string]string `json:"categories,omitempty"`
	Subdomains                     []string          `json:"subdomains,omitempty"`
	Resolutions                    []Resolution      `json:"resolutions,omitempty"`
	UndetectedCommunicatingSamples []DetectedSample  `json:"undetected_communicating_samples,omitempty"`
	UndetectedDownloadedSamples    []DetectedSample  `json:"undetected_downloaded_samples,omitempty"`
	UndetectedReferrerSamples      []DetectedSample  `json:"undetected_referrer_samples,omitempty"`
}

// DetectedSample represents a sample detection structure
type DetectedSample struct {
	Date      string `json:"date"`
	Positives int    `json:"positives"`
	SHA256    string `json:"sha256"`
	Total     int    `json:"total"`
}

// Resolution represents IP resolution history
type Resolution struct {
	LastResolved string `json:"last_resolved"`
	IPAddress    string `json:"ip_address"`
}

// VirusTotalChecker handles the VirusTotal API interactions
type VirusTotalChecker struct {
	baseURL string
	client  *resty.Client
}

// NewVirusTotalChecker creates a new instance of VirusTotalChecker
func NewVirusTotalChecker() *VirusTotalChecker {
	client := resty.New()
	client.SetTimeout(30 * time.Second)
	client.SetHeaders(map[string]string{
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept":       "application/json",
		"Content-Type": "application/json",
	})

	return &VirusTotalChecker{
		baseURL: "https://www.virustotal.com/vtapi/v2/domain/report",
		client:  client,
	}
}

func (v *VirusTotalChecker) CheckDomain() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your VirusTotal API key: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)

	fmt.Print("Enter domain to check: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	// Make API request
	resp, err := v.client.R().
		SetQueryParams(map[string]string{
			"apikey": apiKey,
			"domain": domain,
		}).
		Get(v.baseURL)

	if err != nil {
		return fmt.Errorf("network error: %v", err)
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("error: status code %d - %s", resp.StatusCode(), resp.String())
	}

	// Parse the raw JSON response first
	var rawData map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &rawData); err != nil {
		return fmt.Errorf("error parsing raw JSON response: %v", err)
	}

	// Print raw response first (matching Python's behavior)
	fmt.Println("\n=== Domain Analysis Results ===")
	rawJSON, _ := json.MarshalIndent(rawData, "", "  ")
	fmt.Println(string(rawJSON))

	// Now parse into our structured response
	var result VirusTotalResponse
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return fmt.Errorf("error parsing structured JSON response: %v", err)
	}

	// Display BitDefender Analysis if available
	if result.BitDefenderInfo != "" {
		fmt.Println("\n=== BitDefender Analysis ===")
		fmt.Println(result.BitDefenderInfo)
	}

	// Display Detected Communicating Samples
	if len(result.DetectedCommunicatingSamples) > 0 {
		fmt.Println("\n=== Detected Communicating Samples ===")
		for _, sample := range result.DetectedCommunicatingSamples {
			fmt.Printf("Date: %s\n", sample.Date)
			fmt.Printf("Positives/Total: %d/%d\n", sample.Positives, sample.Total)
			fmt.Printf("SHA256: %s\n", sample.SHA256)
			fmt.Println("---")
		}
	}

	// Display Detected Downloaded Samples
	if len(result.DetectedDownloadedSamples) > 0 {
		fmt.Println("\n=== Detected Downloaded Samples ===")
		for _, sample := range result.DetectedDownloadedSamples {
			fmt.Printf("Date: %s\n", sample.Date)
			fmt.Printf("Positives/Total: %d/%d\n", sample.Positives, sample.Total)
			fmt.Printf("SHA256: %s\n", sample.SHA256)
			fmt.Println("---")
		}
	}

	// Display Detected Referrer Samples
	if len(result.DetectedReferrerSamples) > 0 {
		fmt.Println("\n=== Detected Referrer Samples ===")
		for _, sample := range result.DetectedReferrerSamples {
			fmt.Printf("Date: %s\n", sample.Date)
			fmt.Printf("Positives/Total: %d/%d\n", sample.Positives, sample.Total)
			fmt.Printf("SHA256: %s\n", sample.SHA256)
			fmt.Println("---")
		}
	}

	return nil
}

func main() {
	checker := NewVirusTotalChecker()
	if err := checker.CheckDomain(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
