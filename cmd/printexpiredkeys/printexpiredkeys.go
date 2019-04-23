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

	expiredKeys, err := datastore.ListExpiredKeys()
	if err != nil {
		fmt.Printf("error sending emails: %v\n", err)
		os.Exit(1)
	}

	for i := range expiredKeys {
		email, err := expiredKeys[i].Email()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", email)
	}
}
