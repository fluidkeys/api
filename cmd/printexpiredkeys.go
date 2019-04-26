package cmd

import (
	"fmt"
	"strings"

	"github.com/fluidkeys/api/datastore"
)

func PrintExpiredKeys() (exitCode int) {
	expiredKeys, err := datastore.ListExpiredKeys()
	if err != nil {
		fmt.Printf("error listing expired keys: %v\n", err)
		return 1
	}

	fmt.Printf("fingerprint,verified_emails,unverified_emails\n")
	for _, expiredKey := range expiredKeys {
		fmt.Printf("%s,\"%s\",\"%s\"\n",
			expiredKey.UserProfile.Key.Fingerprint().Hex(),
			strings.Join(expiredKey.VerifiedEmails, ","),
			strings.Join(expiredKey.UnverifiedEmails, ","))
	}
	return 0
}
