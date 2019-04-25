package datastore

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

// ListExpiredKeys returns all pgp keys that have expired.
func ListExpiredKeys() (keys []*pgpkey.PgpKey, err error) {
	query := `SELECT keys.armored_public_key,
                     email_key_link.email
              FROM email_key_link
              INNER JOIN keys                ON email_key_link.key_id = keys.id`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var armoredPublic string
		var verifiedEmail string
		err = rows.Scan(&armoredPublic, &verifiedEmail)
		if err != nil {
			return nil, err
		}

		key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublic)
		if err != nil {
			log.Printf("error loading key: %v", err)
			continue
		}

		if !doesPrimaryEmailMatch(key, verifiedEmail) {
			continue
		}

		if anyUIDHasExpired(key, time.Now()) {
			keys = append(keys, key)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// GetTimeLastSent returns the most recent the given email type was sent to the given key, or
// nil if there's no record of it being sent
func GetTimeLastSent(txn *sql.Tx, emailTemplateID string, userProfileUUID uuid.UUID) (
	*time.Time, error) {

	if emailTemplateID == "" {
		return nil, fmt.Errorf("invalid emailTemplateID: cannot be empty")
	}

	query := `SELECT sent_at
              FROM emails_sent
			  WHERE email_template_id=$1
			    AND user_profile_uuid=$2
              ORDER BY sent_at DESC
			  LIMIT 1`

	var sentAt time.Time

	err := transactionOrDatabase(txn).QueryRow(
		query, emailTemplateID, userProfileUUID,
	).Scan(&sentAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &sentAt, nil
}

func doesPrimaryEmailMatch(key *pgpkey.PgpKey, email string) bool {
	keyEmail, err := key.Email()
	if err != nil {
		log.Printf("error getting email for key: %v", err)
		return false
	}

	return emailMatches(keyEmail, email)
}

func emailMatches(firstEmail string, secondEmail string) bool {
	// TODO: make this less naive
	return strings.ToLower(firstEmail) == strings.ToLower(secondEmail)
}

// anyUIDHasExpired returns true if all these things are true:
// * it has an encryption subkey (TODO)
// * its primary user ID has not expired
//   - note: we just check if *any* user id has expired, and call that invalid.
func anyUIDHasExpired(key *pgpkey.PgpKey, now time.Time) bool {
	for _, id := range key.Identities {
		hasExpiry, expiryTime := pgpkey.CalculateExpiry(
			key.PrimaryKey.CreationTime, // not to be confused with the time of the *signature*
			id.SelfSignature.KeyLifetimeSecs,
		)
		if !hasExpiry {
			continue
		}

		if hasExpired := expiryTime.Before(now); hasExpired == true {
			return true
		}
	}
	return false
}
