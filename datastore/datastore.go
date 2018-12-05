package datastore

import (
	"database/sql"
	"fmt"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	databaseUrl, present := os.LookupEnv("DATABASE_URL")

	if !present {
		panic("Missing DATABASE_URL, it should be e.g. " +
			"postgres://vagrant:password@localhost:5432/vagrant")
	}

	err := Initialize(databaseUrl)
	if err != nil {
		panic(err)
	}
}

// Initialize initialises a postgres database from the given databaseUrl
func Initialize(databaseUrl string) error {
	var err error
	db, err = sql.Open("postgres", databaseUrl)
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	return nil
}

func GetArmoredPublicKeyForEmail(email string) (armoredPublicKey string, found bool, err error) {
	query := `SELECT email_key_link.email,
	                 keys.armored_public_key
		  FROM email_key_link
		  LEFT JOIN keys ON email_key_link.key_id = keys.id
		  WHERE email_key_link.email=$1`

	var gotEmail string

	err = db.QueryRow(query, email).Scan(&gotEmail, &armoredPublicKey)
	if err == sql.ErrNoRows {
		return "", false, nil // return found=false without an error

	} else if err != nil {
		return "", false, err
	}

	if email != gotEmail {
		panic(fmt.Errorf("queried for '%s', got back '%s'", email, gotEmail))
	}

	return armoredPublicKey, true, nil
}

func GetArmoredPublicKeyForFingerprint(fpr fingerprint.Fingerprint) (armoredPublicKey string, found bool, err error) {
	dbFingerprint := fmt.Sprintf("4:%s", fpr.Hex())

	query := `SELECT keys.armored_public_key
		  FROM keys
		  WHERE keys.fingerprint=$1`

	err = db.QueryRow(query, dbFingerprint).Scan(&armoredPublicKey)
	if err == sql.ErrNoRows {
		return "", false, nil // return found=false without an error

	} else if err != nil {
		return "", false, err
	}

	return armoredPublicKey, true, nil
}

// CreateSecret stores the armoredEncryptedSecret (which must be encrypted to
// the given `recipientFingerprint`) against the recipient public key.
func CreateSecret(recipientFingerprint fingerprint.Fingerprint, armoredEncryptedSecret string, now time.Time) error {
	secretUUID, err := uuid.NewV4()
	if err != nil {
		return err
	}

	createdAt := now

	dbFingerprint := fmt.Sprintf("4:%s", recipientFingerprint.Hex())

	query := `INSERT INTO secrets(
                      recipient_key_id,
                      uuid,
                      created_at,
                      armored_encrypted_secret)
                  VALUES (
                      (SELECT id FROM keys WHERE fingerprint=$1),
                      $2,
                      $3,
                      $4)`

	_, err = db.Exec(
		query,
		dbFingerprint,
		secretUUID,
		createdAt,
		armoredEncryptedSecret,
	)
	if err != nil {
		return err
	}
	return nil
}
