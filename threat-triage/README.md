# Threat Triage CLI

**Threat Triage CLI** is a CLI reconnaissance tool for threat triage. It takes _inbound noise_ such as automated scans, bots, misconfigured devices and enriches them using various threat intelligence API's like Virus Total, Shodan, etc...

## Tech stack
- [Go](https://go.dev/)
- [Cobra CLI framework](https://cobra.dev/)
- [go-fuzzyfinder](https://github.com/ktr0731/go-fuzzyfinder) for interactive selection in the terminal
- Various threat intelligence APIs for data enrichment (e.g., [Virus Total](https://www.virustotal.com/), [Shodan](https://www.shodan.io/))

## Usage & Examples

`blacklist [COUNT]`
Interactively browse and select an IP address from a list to view its threat intelligence report.

`ipreport <IP_ADDRESS>`
Directly fetch a threat intelligence report for a specific IP address.

`filereport <FILE_HASH>`    
Show a report for a specific file hash

## Set environment variables

```bash
VT_API_KEY=<API_KEY>
SHODAN_API_KEY=<API_KEY>
```

## Example

https://github.com/user-attachments/assets/59ec4678-321d-4b6e-9fb2-cabba43411b2

