package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fluidkeys/api/datastore"
)

func main() {
	err := datastore.Initialize(datastore.MustReadDatabaseURL())
	if err != nil {
		panic(err)
	}

	expiredKeys, err := datastore.ListExpiredKeys()
	if err != nil {
		fmt.Printf("error listing expired keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("fingerprint,verified_emails,unverified_emails\n")
	for _, expiredKey := range expiredKeys {
		fmt.Printf("%s,\"%s\",\"%s\"\n",
			expiredKey.UserProfile.Key.Fingerprint().Hex(),
			strings.Join(expiredKey.VerifiedEmails, ","),
			strings.Join(expiredKey.UnverifiedEmails, ","))
	}
}
