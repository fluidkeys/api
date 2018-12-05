package datastore

import (
	"database/sql"
	"fmt"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

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

func GetArmoredPublicKeyForFingerprint(fingerprint fpr.Fingerprint) (armoredPublicKey string, found bool, err error) {
	query := `SELECT keys.armored_public_key
		  FROM keys
		  WHERE keys.fingerprint=$1`

	err = db.QueryRow(query, dbFormat(fingerprint)).Scan(&armoredPublicKey)
	if err == sql.ErrNoRows {
		return "", false, nil // return found=false without an error

	} else if err != nil {
		return "", false, err
	}

	return armoredPublicKey, true, nil
}

// CreateSecret stores the armoredEncryptedSecret (which must be encrypted to
// the given `recipientFingerprint`) against the recipient public key.
func CreateSecret(recipientFingerprint fpr.Fingerprint, armoredEncryptedSecret string, now time.Time) error {
	secretUUID, err := uuid.NewV4()
	if err != nil {
		return err
	}

	createdAt := now

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
		dbFormat(recipientFingerprint),
		secretUUID,
		createdAt,
		armoredEncryptedSecret,
	)
	if err != nil {
		return err
	}
	return nil
}

func GetSecrets(recipientFingerprint fpr.Fingerprint) ([]*secret, error) {
	secrets := make([]*secret, 0)

	query := `SELECT secrets.armored_encrypted_secret, secrets.uuid
	          FROM secrets
		  LEFT JOIN keys ON secrets.recipient_key_id=keys.id
		  WHERE keys.fingerprint=$1`

	rows, err := db.Query(query, dbFormat(recipientFingerprint))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		secret := secret{}
		err = rows.Scan(&secret.ArmoredEncryptedSecret, &secret.SecretUUID)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, &secret)
	}
	err = rows.Err()

	if err != nil {
		return nil, err
	}

	return secrets, nil
}

func DeleteSecret(secretUUID uuid.UUID, recipientFingerprint fpr.Fingerprint) (found bool, err error) {
	query := `DELETE FROM secrets
	          USING keys
	          WHERE secrets.recipient_key_id = keys.id
	          AND secrets.uuid=$1
		  AND keys.fingerprint=$2`

	result, err := db.Exec(query, secretUUID, dbFormat(recipientFingerprint))
	if err != nil {
		return false, err
	}

	numRowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if numRowsAffected < 1 {
		return false, nil // not found (but no error)
	}

	return true, nil // found and deleted
}

func MustReadDatabaseUrl() string {
	databaseUrl, present := os.LookupEnv("DATABASE_URL")

	if !present {
		panic("Missing DATABASE_URL, it should be e.g. " +
			"postgres://vagrant:password@localhost:5432/vagrant")
	}
	return databaseUrl
}

func Migrate() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	for _, sql := range migrateDatabaseStatements {
		_, err := tx.Exec(sql)
		if err != nil {
			return fmt.Errorf("error (rolling back everything): %v", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func dbFormat(fingerprint fpr.Fingerprint) string {
	return fmt.Sprintf("4:%s", fingerprint.Hex())
}

type secret struct {
	ArmoredEncryptedSecret string
	SecretUUID             string
	CreatedAt              time.Time
}
