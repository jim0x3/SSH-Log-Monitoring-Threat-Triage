package filereport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type FileReport struct {
	Data struct {
		Id         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			TypeExtension string `json:"type_extension"`
			Size          int    `json:"size"`
		} `json:"attributes"`
	} `json:"data"`
}

// FileReportError represents the VirusTotal API error response payload
type FileReportError struct {
	Error struct {
		Code         string `json:"code"`
		ErrorMessage string `json:"message"`
	} `json:"error"`
}

// GetFileReport fetches a file report from VirusTotal for the given hash.
func GetFileReport(hash string) (FileReport, error) {
	var f FileReport
	if hash == "" {
		return f, fmt.Errorf("hash cannot be empty")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	apiKey := os.Getenv("VT_API_KEY")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return FileReport{}, fmt.Errorf("malformed URL, check for misspellings %s", err)
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	var c = &http.Client{
		Timeout: 5 * time.Second,
	}

	res, err := c.Do(req)
	if err != nil {
		return f, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var e FileReportError
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return f, fmt.Errorf("API returned status %d and failed to decode error response: %w", res.StatusCode, err)
		}
		return f, fmt.Errorf("API returned status %d: %s - %s", res.StatusCode, e.Error.Code, e.Error.ErrorMessage)
	}

	if err := json.NewDecoder(res.Body).Decode(&f); err != nil {
		return f, fmt.Errorf("decode failed: %w", err)
	}

	return f, nil
}
