package cmd

import (
	"fmt"
	"strconv"

	"github.com/jim3/mazey/internal/blacklist"
	"github.com/jim3/mazey/internal/ipreport"
	"github.com/ktr0731/go-fuzzyfinder"
	"github.com/spf13/cobra"
)

var blacklistCmd = &cobra.Command{
	Use:   "blacklist [COUNT]",
	Short: "Fetches blacklisted IPs and and enriches them using various threat intelligence API's",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		count := 10
		if len(args) > 0 {
			parsedCount, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid count %q: %w", args[0], err)
			}
			count = parsedCount
		}

		ipSlc, err := blacklist.GetBlacklist(count)
		if err != nil {
			return err
		}

		// Uses the go-fuzzyfinder library to allow the user to select an IP from the list
		// Find returns the index `idx` of the selected item
		idx, err := fuzzyfinder.Find(
			ipSlc,
			func(i int) string {
				return ipSlc[i] // How to display the item in the list
			},
			fuzzyfinder.WithPreviewWindow(func(i int, width int, height int) string {
				if i == -1 {
					return "No selection"
				}
				return fmt.Sprintf("Information for: %s\n(Fetching details...)", ipSlc[i])
			}),
		)

		if err != nil {
			return fmt.Errorf("fuzzy finder failed: %w", err)
		}

		report, err := ipreport.MergeReports(ipSlc[idx], 3)
		if err != nil {
			return err
		}

		PrintFinalReport(report)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(blacklistCmd)
}
