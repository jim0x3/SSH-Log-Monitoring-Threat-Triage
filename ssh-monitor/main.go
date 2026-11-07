package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
)

const maxInputLineSize = 1024 * 1024

var failedPasswordPattern = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from ([0-9.]+) port \d+`)

type journalEntry struct {
	Message string `json:"MESSAGE"`
}

func main() {
	if err := run(os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

// ----------------------------------------------

const blacklistPath = "/assets/blacklist.json"

func run(input io.Reader, output io.Writer, diagnostics io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxInputLineSize)

	// Keep track of unique IPs using a map to prevent duplicates
	seenIPs := make(map[string]bool)
	var ips []string

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		var entry journalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			fmt.Fprintf(diagnostics, "line %d: invalid journal JSON: %v\n", lineNumber, err)
			continue
		}

		ip, ok := failedAttemptIP(entry.Message)
		if !ok {
			continue
		}

		// Deduplicate on the fly
		if !seenIPs[ip] {
			seenIPs[ip] = true
			ips = append(ips, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	// Marshal the gathered IPs into a nicely indented JSON array
	data, err := json.MarshalIndent(ips, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blacklist JSON: %w", err)
	}

	// Write directly to your project's assets directory
	if err := os.WriteFile(blacklistPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write blacklist file to %s: %w", blacklistPath, err)
	}

	fmt.Fprintf(output, "Successfully updated blacklist with %d unique IP(s).\n", len(ips))
	return nil
}

// ----------------------------------------------

func failedAttemptIP(message string) (string, bool) {
	match := failedPasswordPattern.FindStringSubmatch(message)
	if match == nil {
		return "", false
	}

	ip := net.ParseIP(match[2])
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	return ip.To4().String(), true
}
