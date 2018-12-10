package datastore

import (
	"database/sql"
	"fmt"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
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

func Ping() error {
	return db.Ping()
}

// UpsertPublicKey either inserts or updates a public key based on the
// fingerprint. For updates, any foreign key relationships are maintained.
func UpsertPublicKey(armoredPublicKey string) error {
	key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		return fmt.Errorf("error loading armored key: %v", err)
	}

	fingerprint := key.Fingerprint()

	query := `INSERT INTO keys (fingerprint, armored_public_key)
	          VALUES ($1, $2)
		  ON CONFLICT (fingerprint) DO UPDATE
		      SET armored_public_key=EXCLUDED.armored_public_key`

	_, err = db.Exec(query, dbFormat(fingerprint), armoredPublicKey)

	return err
}

// DeletePublicKey deletes a key by its fingerprint, returning found=true if
// a matching key was found and deleted.
// Note that any linked emails and stored secrets will also be deleted.
// If there was no matching key (e.g. it was already deleted), found is false
// and error is nil.
// An error is returned only if something failed e.g. a database error.
func DeletePublicKey(fingerprint fpr.Fingerprint) (found bool, err error) {
	query := `DELETE FROM keys WHERE keys.fingerprint=$1`

	result, err := db.Exec(query, dbFormat(fingerprint))
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

// LinkEmailToFingerprint records that the given public key should be returned
// when queried for the given email address.
// If there is no public key in the database matching the fingerprint, an
// error will be returned.
func LinkEmailToFingerprint(email string, fingerprint fpr.Fingerprint) error {
	query := `INSERT INTO email_key_link (email, key_id)
	          VALUES($1, (SELECT id FROM keys WHERE fingerprint=$2))
		  ON CONFLICT(email) DO UPDATE
		      SET key_id=EXCLUDED.key_id`

	_, err := db.Exec(query, email, dbFormat(fingerprint))
	return err
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

func getKeyIdForFingerprint(fingerprint fpr.Fingerprint) (keyId int64, found bool, err error) {
	query := `SELECT keys.id FROM keys WHERE fingerprint=$1`

	err = db.QueryRow(query, dbFormat(fingerprint)).Scan(&keyId)
	if err == sql.ErrNoRows {
		return 0, false, nil // return found=false without an error

	} else if err != nil {
		return 0, false, err
	}

	return keyId, true, nil
}

// CreateSecret stores the armoredEncryptedSecret (which must be encrypted to
// the given `recipientFingerprint`) against the recipient public key.
func CreateSecret(recipientFingerprint fpr.Fingerprint, armoredEncryptedSecret string, now time.Time) (*uuid.UUID, error) {
	secretUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	keyId, found, err := getKeyIdForFingerprint(recipientFingerprint)

	if err != nil {
		return nil, err
	} else if !found {
		return nil, fmt.Errorf("no key found for fingerprint")
	}

	createdAt := now

	query := `INSERT INTO secrets(
                      recipient_key_id,
                      uuid,
                      created_at,
                      armored_encrypted_secret)
                  VALUES ($1, $2, $3, $4)`

	_, err = db.Exec(
		query,
		keyId,
		secretUUID,
		createdAt,
		armoredEncryptedSecret,
	)
	if err != nil {
		return nil, err
	}
	return &secretUUID, nil
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

func VerifySingleUseNumberNotStored(singleUseUUID uuid.UUID) error {
	query := `SELECT COUNT(uuid) FROM single_use_uuids WHERE uuid=$1`

	var count int
	err := db.QueryRow(query, singleUseUUID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return fmt.Errorf("single use UUID %s already used", singleUseUUID)
	}

	return nil
}

func StoreSingleUseNumber(singleUseUUID uuid.UUID, now time.Time) error {
	query := `INSERT INTO single_use_uuids (uuid, created_at)
	          VALUES ($1, $2)`
	_, err := db.Exec(query, singleUseUUID, now)
	return err
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

func currentDatabaseName() (string, error) {
	query := `SELECT current_database()`

	var databaseName string

	err := db.QueryRow(query).Scan(&databaseName)
	if err != nil {
		return "", err
	}

	return databaseName, nil
}

func DropAllTheTables() error {
	dbName, err := currentDatabaseName()
	if err != nil {
		return fmt.Errorf("failed to get current database name: %v", err)
	}

	switch dbName {
	case "fkapi_test", "travis":
		break
	default:
		return fmt.Errorf("blocking delete of database called %s", dbName)
	}

	var tablesToDrop = []string{
		"email_key_link",
		"secrets",
		"keys",
	}

	for _, table := range tablesToDrop {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table)
		if err != nil {
			return fmt.Errorf("Error dropping table %s: %v", table, err)
		}
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
