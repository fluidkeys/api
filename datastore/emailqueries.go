package datastore

import (
	"log"
	"strings"
	"time"

	"database/sql"
	"fmt"

	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
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
	return keys, nil
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

// ListValidVerifiedKeysNotInTeam returns public keys where:
// * primary email is verified [in SQL]
// * primary email was verified > 3 days ago [in SQL]
// * Key is up to date (hasn't expired) [in code]
// * Not in any team [in code]
func ListValidVerifiedKeysNotInTeam(txn *sql.Tx) (profiles []UserProfile, err error) {
	if txn == nil {
		txn, err = db.Begin()
		if err != nil {
			return nil, fmt.Errorf("error calling db.Begin(): %v", err)
		}
	}

	dbTeams, err := ListAllTeams(txn)
	if err != nil {
		return nil, fmt.Errorf("error getting teams: %v", err)
	}

	allTeams, err := loadTeams(dbTeams)
	if err != nil {
		return nil, fmt.Errorf("error loading teams: %v", err)
	}

	query := `SELECT keys.armored_public_key,
                     email_key_link.email,
                     email_verifications.created_at AS verified_at
              FROM email_key_link
              INNER JOIN keys                ON email_key_link.key_id = keys.id
			  INNER JOIN user_profiles       ON email_key_link.key_id = user_profiles.key_id
              INNER JOIN email_verifications ON email_key_link.email_verification_uuid = email_verifications.uuid
              WHERE email_verifications.created_at < $1`

	now := time.Now()
	threeDaysAgo := now.Add(-time.Duration(24*3) * time.Hour)

	rows, err := txn.Query(query, threeDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var armoredPublic string
		var email string
		var verifiedAt time.Time
		err = rows.Scan(&armoredPublic, &email, &verifiedAt)
		if err != nil {
			return nil, err
		}

		threeDaysAgo := time.Now().Add(-time.Duration(3*24) * time.Hour)
		if verifiedAt.After(threeDaysAgo) {
			log.Printf("key verified too recently, skipping: %s", email)
			continue
		}

		key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublic)
		if err != nil {
			log.Printf("error loading key: %v", err)
			continue
		}

		if !doesPrimaryEmailMatch(key, email) {
			continue
		}
		if !isKeyValid(key, time.Now()) {
			log.Printf("key has expired: %s", key.Fingerprint())
			continue
		}

		if isInATeam(key, allTeams) {
			email, _ = key.Email()
			log.Printf("key is in a team: %s %s", key.Fingerprint(), email)
			continue
		}

		profile := UserProfile{Key: key}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return profiles, nil
}

func loadTeams(dbTeams []*Team) (teams []*team.Team, err error) {
	for i := range dbTeams {
		t := dbTeams[i]
		loadedTeam, err := team.Load(t.Roster, t.RosterSignature)
		if err != nil {
			log.Printf("error loading team %s from roster: %v", t.UUID, err)
			continue
		}
		teams = append(teams, loadedTeam)
	}
	return teams, nil
}

// ListAllTeams returns all teams
func ListAllTeams(txn *sql.Tx) (teams []*Team, err error) {
	query := `SELECT uuid,
                     created_at,
					 roster,
					 roster_signature
			  FROM teams`

	rows, err := transactionOrDatabase(txn).Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {

		team := Team{}
		err = rows.Scan(
			&team.UUID,
			&team.CreatedAt,
			&team.Roster,
			&team.RosterSignature,
		)
		if err != nil {
			return nil, err
		}

		teams = append(teams, &team)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return teams, nil
}

// HaveSentEmail returns whether the emails_sent table contains a record of sending the given email
// (e.g. help_create_join_team_1) to the given profile.
func HaveSentEmail(emailID string, profileUUID uuid.UUID) (bool, error) {
	return false, nil // TODO
}

// RecordSentEmail records into emails_sent table that a given email
// (e.g. help_create_join_team_1) was sent to the given profile
func RecordSentEmail(emailID string, profileUUID uuid.UUID) error {
	return nil // TODO
}

// UserProfile holds information about users (where a user is defined as a pgp public key)
type UserProfile struct {
	UUID                           uuid.UUID
	KeyFirstUploadedAt             *time.Time
	KeyLastUploadedAt              *time.Time
	FirstFkVersion                 string
	CurrentFkVersion               string
	IsSubscribedToReleaseNotes     bool
	IsSubscribedToWeekNotes        bool
	IsSubscribedToFeedback         bool
	PreferencesToken               uuid.UUID
	OptoutEmailsHelpCreateJoinTeam bool
	OptoutEmailsHelpInviteTeam     bool
	OptoutEmailsHelpExpiryWarnings bool
	Key                            *pgpkey.PgpKey
}

// isKeyValid returns true if all these things are true:
// * it has an encryption subkey (TODO)
// * its primary user ID has not expired
//   - note: we just check if *any* user id has expired, and call that invalid.
func isKeyValid(key *pgpkey.PgpKey, now time.Time) bool {
	return !anyUIDHasExpired(key, now)
}

func isInATeam(key *pgpkey.PgpKey, allTeams []*team.Team) bool {
	fingerprintsInATeam := map[fingerprint.Fingerprint]bool{}

	for _, t := range allTeams {
		for _, person := range t.People {
			fingerprintsInATeam[person.Fingerprint] = true
		}
	}

	_, inMap := fingerprintsInATeam[key.Fingerprint()]
	return inMap
}
