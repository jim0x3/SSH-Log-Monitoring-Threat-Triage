// ipreport.go
package cmd

import (
	"github.com/jim3/mazey/internal/ipreport"
	"github.com/spf13/cobra"
)

var ipreportCmd = &cobra.Command{
	Use:   "ipreport <IP_ADDRESS>",
	Short: "Get an IP address report",
	Args:  cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		ipaddr := args[0]

		report, err := ipreport.MergeReports(ipaddr, 3)
		if err != nil {
			return err
		}

		PrintFinalReport(report)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(ipreportCmd)
	// Here you will define your flags and configuration settings.
}
