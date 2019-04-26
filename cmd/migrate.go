package cmd

import (
	"fmt"
	"github.com/fluidkeys/api/datastore"
)

func Migrate() (exitCode int) {
	fmt.Print("Running database migrations.\n")

	err := datastore.Migrate()
	if err != nil {
		fmt.Printf("error running datastore.Migrate(): %v", err)
		return 1
	}

	fmt.Print("Done.\n")
	return 0
}
