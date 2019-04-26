package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/email"
)

func DeleteExpiredKeys() (exitCode int) {
	expiredKeys, err := datastore.ListExpiredKeys()
	if err != nil {
		fmt.Printf("error listing expired keys: %v\n", err)
		return 1
	}

	var keysDeleted int
	var emailsSent int
	var errorsSeen int

	for _, expiredKey := range expiredKeys {
		fmt.Printf("deleting key %s (verified emails: %s)",
			expiredKey.UserProfile.Key.Fingerprint().Hex(),
			strings.Join(expiredKey.VerifiedEmails, ", "))

		if len(expiredKey.VerifiedEmails) > 0 {
			err := email.SendKeyExpiredDeleted(
				expiredKey.UserProfile.UUID,
				expiredKey.VerifiedEmails[0],
				expiredKey.UserProfile.Key.Fingerprint(),
			)

			if err != nil {
				log.Printf("%s error sending email: %v",
					expiredKey.UserProfile.Key.Fingerprint(), err,
				)
				errorsSeen++
				// carry on and delete the key anyway
			} else {
				emailsSent++
			}

		}

		_, err := datastore.DeletePublicKey(expiredKey.UserProfile.Key.Fingerprint())
		if err != nil {
			log.Printf("error calling DeletePublicKey(%s): %v",
				expiredKey.UserProfile.Key.Fingerprint(), err)
			errorsSeen++
			continue
		} else {
			keysDeleted++
		}
	}

	fmt.Printf("%d keys deleted, %d emails sent, %d errors\n", keysDeleted, emailsSent, errorsSeen)
	if errorsSeen > 0 {
		return 1
	}
	return 0
}
