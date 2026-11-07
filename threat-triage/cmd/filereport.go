package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jim3/mazey/internal/filereport"
	"github.com/spf13/cobra"
)

// filereportCmd represents the filereport command
var filereportCmd = &cobra.Command{
	Use:   "filereport <HASH>",
	Short: "Retrieve information about a file",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("filereport called")
		filehash := args[0]

		header := color.New(color.FgHiCyan).Add(color.Bold)
		danger := color.New(color.FgRed).Add(color.Bold)
		warning := color.New(color.FgYellow)
		success := color.New(color.FgGreen)
		label := color.New(color.FgHiBlack)

		res, err := filereport.GetFileReport(filehash)
		if err != nil {
			return err
		}
		report := res.Data.Attributes

		header.Printf("FILE REPORT FOR: %s\n", res.Data.Id)
		success.Printf("FILE REPORT FOR: %s\n", res.Data.Id)
		label.Println("====================================================")
		danger.Printf("FILE EXTENSION: %s\n", report.TypeExtension)
		warning.Printf("SIZE: %d\n", report.Size)
		fmt.Println()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(filereportCmd)
}
