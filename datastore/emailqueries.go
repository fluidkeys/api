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

// RecordSentEmail records that the given email type was sent to the given key
func RecordSentEmail(txn *sql.Tx, emailTemplateID string, userProfileUUID uuid.UUID, now time.Time) error {
	var count int
	if err := transactionOrDatabase(txn).QueryRow(
		"SELECT count(*) FROM user_profiles WHERE uuid=$1", userProfileUUID,
	).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no such user profile with UUID %s", userProfileUUID)
	}

	query := `INSERT INTO emails_sent(
                  sent_at,
                  user_profile_uuid,
				  email_template_id
              )
	          VALUES ($1, $2, $3)`

	_, err := transactionOrDatabase(txn).Exec(query, now, userProfileUUID, emailTemplateID)
	if err != nil {
		return fmt.Errorf("error inserting into db: %v", err)
	}
	return nil
}

func doesPrimaryEmailMatch(key *pgpkey.PgpKey, email string) bool {
	keyEmail, err := key.Email()
	if err != nil {
		log.Printf("error getting email for key: %v", err)
		return false
	}

	return emailMatches(keyEmail, email)
}

// CanSendWithRateLimit looks up the last time we sent a given (user profile + email template)
// combination in the database, and returns whether we're past the given rateLimit duration.
//
// For example, if we want to ensure we don't send `template_1` to `profile_1` more than once
// per hour, we could use it like this:
//
// > canSendWithRateLimit(profile_1, template_1, time.Duration(1) * time.Hour)
//
// note that a rateLimit of `nil` means *unlimited* and will always return true. *use with care!*
//
// for emails intended to be sent only once (e.g. onboarding emails), consider using 1 year.
// this way, we avoid completely stale information, and the person will get an (infrequent) reminder
// that we still hold their information, giving them an opportunity to ask us to delete it.
func CanSendWithRateLimit(
	emailTemplateID string,
	userProfileUUID uuid.UUID,
	rateLimit *time.Duration,
	now time.Time,
) (bool, error) {

	if rateLimit == nil {
		return true, nil
	}

	timeLastSent, err := GetTimeLastSent(nil, emailTemplateID, userProfileUUID)
	if err != nil {
		return false, err
	}

	if timeLastSent == nil {
		// never sent this type of email before to this user profile
		return true, nil
	}

	nextAllowed := timeLastSent.Add(*rateLimit)

	return now.After(nextAllowed), nil
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
