package main

import (
	"log"

	"github.com/jim3/mazey/cmd"
	"github.com/joho/godotenv"
)

func main() {
	// Load the .env file from the root directory
	err := godotenv.Load()
	// check the error here just to be sure
	if err != nil {
		log.Println("Note: No .env file found, using system environment variables.")
	}
	cmd.Execute()
}
