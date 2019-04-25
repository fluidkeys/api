package datastore

import (
	"database/sql"
	"fmt"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

// UserProfile represents data in the user_profiles table
type UserProfile struct {
	UUID                       uuid.UUID
	OptoutEmailsExpiryWarnings bool
	KeyID                      int

	Key *pgpkey.PgpKey
}

func (up *UserProfile) loadKey(txn *sql.Tx) error {
	var err error

	if up.KeyID == 0 {
		panic("keyID has not been set")
	}
	up.Key, err = loadKey(txn, up.KeyID)
	return err
}

func loadUserProfile(txn *sql.Tx, keyID int) (*UserProfile, error) {
	profile := UserProfile{}

	var count int
	err := transactionOrDatabase(txn).QueryRow(
		"SELECT COUNT(*) FROM keys WHERE id=$1", keyID,
	).Scan(&count)

	if err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, fmt.Errorf("no such key with id %d", keyID)
	}

	query := `SELECT user_profiles.uuid,
                     user_profiles.optout_emails_expiry_warnings,
					 user_profiles.key_id
			  FROM user_profiles 
			  WHERE user_profiles.key_id=$1`

	err = transactionOrDatabase(txn).QueryRow(query, keyID).Scan(
		&profile.UUID,
		&profile.OptoutEmailsExpiryWarnings,
		&profile.KeyID,
	)
	if err == sql.ErrNoRows {
		// no user profile found: create one
		var p *UserProfile
		if p, err = createUserProfile(txn, keyID); err != nil {
			return nil, fmt.Errorf(
				"no user profile for key ID %d, and couldn't make one: %s", keyID, err)
		}
		profile = *p // copy contents of created p into profile

	} else if err != nil {
		return nil, err
	}

	if err = profile.loadKey(txn); err != nil {
		return nil, fmt.Errorf("error loading key: %v", err)
	}

	return &profile, nil
}

func getKeyID(txn *sql.Tx, fingerprint fpr.Fingerprint) (keyID int, err error) {
	query := `SELECT keys.id FROM keys WHERE keys.fingerprint=$1`

	err = transactionOrDatabase(txn).QueryRow(query, dbFormat(fingerprint)).Scan(&keyID)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("no key found with fingerprint %s", fingerprint)
	} else if err != nil {
		return 0, err
	}

	return keyID, nil
}

func loadKey(txn *sql.Tx, keyID int) (key *pgpkey.PgpKey, err error) {
	query := `SELECT keys.armored_public_key FROM keys WHERE keys.id=$1`

	var armoredPublicKey string

	err = transactionOrDatabase(txn).QueryRow(query, keyID).Scan(&armoredPublicKey)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no key found with key ID %d", keyID)
	} else if err != nil {
		return nil, err
	}

	key, err = pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error loading key: %v", err)
	}

	return key, nil
}

func createUserProfile(txn *sql.Tx, keyID int) (*UserProfile, error) {
	uniqueUUID, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("error generating UUID: %v", err)
	}

	profile := &UserProfile{
		UUID: uniqueUUID,
		OptoutEmailsExpiryWarnings: false,
		KeyID: keyID,
	}

	query := `INSERT INTO user_profiles(
                  uuid,
				  optout_emails_expiry_warnings,
				  key_id
              )
	          VALUES ($1, $2, $3)`

	_, err = transactionOrDatabase(txn).Exec(
		query, profile.UUID, profile.OptoutEmailsExpiryWarnings, keyID,
	)
	if err != nil {
		return nil, fmt.Errorf("error inserting into db: %v", err)
	}

	return loadUserProfile(txn, keyID)
}
