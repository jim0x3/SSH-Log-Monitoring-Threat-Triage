package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
)

// GetBlacklist returns a `[]string` of IPs from the `assets/blacklist.json` file.
func GetBlacklist(count int) ([]string, error) {
	var ips []string
	filePath := "assets/blacklist.json"

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blacklist file: %w", err)
	}

	if err := json.Unmarshal(data, &ips); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	if count > len(ips) {
		count = len(ips)
	}

	return ips[:count], nil
}
