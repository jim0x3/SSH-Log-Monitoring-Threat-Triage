# SSH Monitor

SSH Monitor is a tool that parses SSH service logs from `journalctl` and extracts failed login attempts, updating and writing to a blacklist.json file to the the threat triage system for further action.

## Usage

The tool reads from standard input and writes the updated blacklist to `assets/blacklist.json`.
### Example

```bash
journalctl -o json -u ssh.service | ./out
```

