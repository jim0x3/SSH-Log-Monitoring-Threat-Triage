package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jim3/mazey/internal/ipreport"
)

// PrintFinalReport formats and prints the threat intelligence report to the console.
func PrintFinalReport(report ipreport.FinalReport) {
	danger := color.New(color.FgRed).Add(color.Bold)
	warning := color.New(color.FgYellow)
	success := color.New(color.FgGreen)
	info := color.New(color.FgCyan)
	dim := color.New(color.FgHiBlack).SprintFunc()

	divider := dim("------------------------------------------------------------")
	fmt.Println(divider)
	info.Printf("IP: %s\nASN: %d\nCountry: %s\nRep: %d\nNetwork: %s\n",
		report.IP, report.ASN, report.Country, report.Reputation, report.Network)
	fmt.Println(divider)
	
	if report.Stats.Malicious > 0 {
		danger.Printf("MALICIOUS:  %d\n", report.Stats.Malicious)
	} else {
		success.Println("✅ MALICIOUS:  0 (Clean)")
	}
	
	if report.Stats.Suspicious > 0 {
		warning.Printf("SUSPICIOUS: %d\n", report.Stats.Suspicious)
	} else {
		success.Println("✅ SUSPICIOUS:  0 (Clean)")
	}
	
	fmt.Println(divider)
	info.Println("Recent domain names that have pointed to this IP:")
	for _, v := range report.Resolutions {
		info.Printf("- %s\n", v.HostName)
	}
	fmt.Println(divider)
}
