package main

import (
	"fmt"
	"os"

	"github.com/fluidkeys/api/datastore"
)

func main() {
	err := datastore.Initialize(datastore.MustReadDatabaseURL())
	if err != nil {
		panic(err)
	}

	if err := datastore.CreateMissingUserProfiles(); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}
