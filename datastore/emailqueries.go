package datastore

import (
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

type keyExpiring = struct {
	UserProfile     *UserProfile
	DaysUntilExpiry int
	PrimaryEmail    string
}

// ListKeysExpiring lists keys expiring in the next 15 days
func ListKeysExpiring() (keys []keyExpiring, err error) {
	query := `SELECT keys.id,
                     keys.armored_public_key,
                     email_key_link.email
              FROM email_key_link
              INNER JOIN keys                ON email_key_link.key_id = keys.id`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var keyID int
		var armoredPublic string
		var verifiedEmail string
		err = rows.Scan(&keyID, &armoredPublic, &verifiedEmail)
		if err != nil {
			return nil, err
		}

		key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublic)
		if err != nil {
			log.Printf("error loading key: %v", err)
			continue
		}

		primaryEmail, err := key.Email()
		if err != nil {
			log.Printf("%s error getting primary email: %v", key.Fingerprint().Hex(), err)
		}

		if !doesPrimaryEmailMatch(key, verifiedEmail) {
			log.Printf("%s primary email %s != verified email %s\n",
				key.Fingerprint().Hex(), primaryEmail, verifiedEmail)
			continue
		}

		nextExpiry := getEarliestExpiry(key)
		if nextExpiry == nil {
			// no UIDs expire. ignore this key.
			log.Printf("%s ignoring key with no expiry\n", key.Fingerprint())
			continue
		}

		now := time.Now()
		day := time.Duration(24) * time.Hour

		fifteenDaysFromNow := now.Add(15 * day)

		if nextExpiry.Before(now) || nextExpiry.After(fifteenDaysFromNow) {
			continue
		}

		daysUntilExpiry := int(nextExpiry.Sub(now).Round(day).Seconds() / 86400)

		profile, err := loadUserProfile(nil, keyID)
		if err != nil {
			log.Printf("%s can't load user profile: %v", key.Fingerprint().Hex(), err)
			continue
		}

		if profile.OptoutEmailsExpiryWarnings {
			log.Printf("%s is opted out of receiving expiry emails", key.Fingerprint().Hex())
			continue
		}

		keys = append(keys, keyExpiring{
			DaysUntilExpiry: daysUntilExpiry,
			PrimaryEmail:    primaryEmail,
			UserProfile:     profile,
		})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

type expiredKey = struct {
	Key              *pgpkey.PgpKey
	VerifiedEmails   []string
	UnverifiedEmails []string
}

// ListExpiredKeys returns all PGP keys that have expired. It populates VerifiedEmail with any
// email on the key that's verified, preferably the "primary" UID but falling back to any
// verified email.
func ListExpiredKeys() (expiredKeys []expiredKey, err error) {
	query := `SELECT keys.armored_public_key FROM keys`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var armoredPublic string
		err = rows.Scan(&armoredPublic)
		if err != nil {
			return nil, err
		}

		key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublic)
		if err != nil {
			log.Printf("error loading key: %v", err)
			continue
		}

		if !anyUIDHasExpired(key, time.Now()) {
			continue
		}

		result := expiredKey{Key: key}

		for _, email := range key.Emails(true) {
			isVerified, err := QueryEmailVerifiedForFingerprint(nil, email, key.Fingerprint())
			if err != nil {
				log.Printf("error calling QueryEmailVerifiedForFingerprint: %v", err)

			} else if isVerified {
				result.VerifiedEmails = append(result.VerifiedEmails, email)

			} else {
				result.UnverifiedEmails = append(result.UnverifiedEmails, email)
			}
		}
		expiredKeys = append(expiredKeys, result)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return expiredKeys, nil
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
	earliestExpiry := getEarliestExpiry(key)
	if earliestExpiry == nil {
		return false
	}

	if hasExpired := earliestExpiry.Before(now); hasExpired == true {
		return true
	}
	return false
}

// getSortedUIDExpiries returns the expiry times of the key's UIDs in order from earliest (past)
// to latest (future).
func getSortedUIDExpiries(key *pgpkey.PgpKey) []time.Time {
	expiries := []time.Time{}

	for _, id := range key.Identities {
		hasExpiry, expiryTime := pgpkey.CalculateExpiry(
			key.PrimaryKey.CreationTime, // not to be confused with the time of the *signature*
			id.SelfSignature.KeyLifetimeSecs,
		)
		if !hasExpiry {
			continue
		}

		expiries = append(expiries, *expiryTime)
	}

	sort.Slice(expiries, func(i, j int) bool { return expiries[i].Before(expiries[j]) })
	return expiries
}

func getEarliestExpiry(key *pgpkey.PgpKey) *time.Time {
	expiries := getSortedUIDExpiries(key)
	if len(expiries) == 0 {
		return nil
	}

	return &expiries[0]
}
