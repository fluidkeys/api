package datastore

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
)

// CreateMissingUserProfiles is a migration to create user profiles with sensible defaults for
// any keys that don't have them
func CreateMissingUserProfiles() error {
	query := `SELECT keys.id
              FROM keys
              LEFT JOIN user_profiles ON keys.id = user_profiles.key_id
			  WHERE user_profiles.uuid IS NULL`

	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	keyIDs := []int{}

	for rows.Next() {
		var keyID int
		err = rows.Scan(&keyID)
		if err != nil {
			return err
		}

		keyIDs = append(keyIDs, keyID)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	for _, keyID := range keyIDs {
		userProfile, err := makeUserProfile(keyID)
		if err != nil {
			return err
		}

		fmt.Printf("inserting default user profile for key ID %d\n", keyID)

		query = `INSERT INTO user_profiles(
			         uuid,
					 key_id,
					 preferences_token,
				     first_fk_version,
				     current_fk_version,
					 key_first_uploaded_at
				 ) VALUES ($1, $2, $3, $4, $5, $6)`
		_, err = db.Exec(
			query,
			userProfile.UUID,
			keyID,
			userProfile.PreferencesToken,
			userProfile.FirstFkVersion,
			userProfile.CurrentFkVersion,
			userProfile.KeyFirstUploadedAt,
		)
		if err != nil {
			return fmt.Errorf("error running `%s`: %v", query, err)
		}
	}

	return nil
}

func makeUserProfile(keyID int) (*UserProfile, error) {
	profile := UserProfile{}
	var err error

	profile.UUID, err = uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to make UUID: %v", err)
	}

	profile.PreferencesToken, err = uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to make UUID: %v", err)
	}

	firstVerif, lastVerif, err := getFirstAndLastVerification(keyID)
	if err != nil {
		return nil, err
	}

	if firstVerif != nil {
		profile.FirstFkVersion = parseUserAgent(firstVerif.UpsertUserAgent)
		profile.KeyFirstUploadedAt = &firstVerif.CreatedAt
	}

	if lastVerif != nil {
		profile.CurrentFkVersion = parseUserAgent(lastVerif.UpsertUserAgent)
	}

	return &profile, nil
}

func parseUserAgent(ua string) (fluidkeysVersion string) {
	if strings.HasPrefix(ua, "fluidkeys-") {
		return strings.TrimPrefix(ua, "fluidkeys-")
	}
	return ""
}

func getFirstAndLastVerification(keyID int) (
	v1 *EmailVerification, v2 *EmailVerification, err error) {

	query := `SELECT created_at,
                     upsert_user_agent
              FROM email_verifications
              WHERE key_id=$1 ORDER BY created_at`

	rows, err := db.Query(query, keyID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	emailVerifications := []*EmailVerification{}

	for rows.Next() {
		ev := EmailVerification{}
		err = rows.Scan(&ev.CreatedAt, &ev.UpsertUserAgent)
		if err != nil {
			return nil, nil, err
		}

		emailVerifications = append(emailVerifications, &ev)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}

	if len(emailVerifications) > 0 {
		return emailVerifications[0], emailVerifications[len(emailVerifications)-1], nil
	}

	return nil, nil, nil
}
