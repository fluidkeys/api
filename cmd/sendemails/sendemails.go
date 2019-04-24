package main

import (
	"fmt"
	"os"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/email"
)

func main() {
	err := datastore.Initialize(datastore.MustReadDatabaseURL())
	if err != nil {
		panic(err)
	}

	if err := email.SendFromCron(); err != nil {
		fmt.Printf("error sending emails: %v\n", err)
		os.Exit(1)
	}
}
