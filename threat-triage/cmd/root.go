package cmd

import (
	"context"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mazey",
	Short: "Go Mazey Go! 🐈 — A threat intelligence triage tool",
	Long:  `Go Mazey Go! 🐈 **Mazey** is an early-stage CLI reconnaissance tool for threat triage.`,
	Example: `mazey blacklist 5
mazey ipreport 211.106.133.202
mazey filereport 9b97edcbd8099796015c78bbf1723b35`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func Execute() {
	// Uses fang to make things *really* pretty.
	err := fang.Execute(context.Background(), rootCmd)
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
