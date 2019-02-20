package main

import (
	"fmt"
	"github.com/fluidkeys/api/datastore"
)

func main() {
	fmt.Print("Running database migrations.\n")

	err := datastore.Initialize(datastore.MustReadDatabaseURL())
	if err != nil {
		panic(err)
	}
	err = datastore.Migrate()
	if err != nil {
		panic(err)
	}

	fmt.Print("Done.\n")
}
