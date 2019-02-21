package datastore

import (
	"database/sql"
	"fmt"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
	"os"
	"strings"
	"time"

	// required rename for SQL
	_ "github.com/lib/pq"
)

var db *sql.DB

// Initialize initialises a postgres database from the given databaseURL
func Initialize(databaseURL string) error {
	var err error
	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	return nil
}

// Ping tests the database and returns an error if there's a problem
func Ping() error {
	return db.Ping()
}

// RunInTransaction begins a new transaction and calls the given `fn` function
// with the transaction.
// If fn returns an error, the transaction will be rolled back and the samme
// error will be returned by RunInTransaction
// If fn returns error=nil, the transaction will be committed (although that
// can fail, in which case an err is returned)
func RunInTransaction(fn func(txn *sql.Tx) error) error {
	txn, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error calling db.Begin(): %v", err)
	}

	if err = fn(txn); err != nil {
		txn.Rollback()
		return err
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	return nil
}

// UpsertPublicKey either inserts or updates a public key based on the
// fingerprint. For updates, any foreign key relationships are maintained.
// txn is a database transaction, or nil to run outside of a transaction
func UpsertPublicKey(txn *sql.Tx, armoredPublicKey string) error {
	key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		return fmt.Errorf("error loading armored key: %v", err)
	}

	fingerprint := key.Fingerprint()

	query := `INSERT INTO keys (fingerprint, armored_public_key)
	          VALUES ($1, $2)
		  ON CONFLICT (fingerprint) DO UPDATE
		      SET armored_public_key=EXCLUDED.armored_public_key`

	_, err = transactionOrDatabase(txn).Exec(query, dbFormat(fingerprint), armoredPublicKey)

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
func LinkEmailToFingerprint(txn *sql.Tx, email string, fingerprint fpr.Fingerprint) error {
	query := `INSERT INTO email_key_link (email, key_id)
	          VALUES($1, (SELECT id FROM keys WHERE fingerprint=$2))
		  ON CONFLICT(email) DO UPDATE
		      SET key_id=EXCLUDED.key_id`

	_, err := transactionOrDatabase(txn).Exec(query, email, dbFormat(fingerprint))
	return err
}

// QueryEmailVerifiedForFingerprint returns true if the given email is verified for the given
// fingerprint.
func QueryEmailVerifiedForFingerprint(txn *sql.Tx, email string, fingerprint fpr.Fingerprint) (bool, error) {
	query := `SELECT COUNT(*)
              FROM email_key_link
			  WHERE email=$1
			  AND key_id=(SELECT id FROM keys WHERE fingerprint=$2)`

	var count int
	err := transactionOrDatabase(txn).QueryRow(query, email, dbFormat(fingerprint)).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetArmoredPublicKeyForEmail returns an ASCII-armored public key for the given email, if the
// email address has been verified.
func GetArmoredPublicKeyForEmail(txn *sql.Tx, email string) (
	armoredPublicKey string, found bool, err error) {

	query := `SELECT email_key_link.email,
	                 keys.armored_public_key
		  FROM email_key_link
		  LEFT JOIN keys ON email_key_link.key_id = keys.id
		  WHERE email_key_link.email=$1`

	var gotEmail string

	err = transactionOrDatabase(txn).QueryRow(query, email).Scan(&gotEmail, &armoredPublicKey)
	if err == sql.ErrNoRows {
		return "", false, nil // return found=false without an error

	} else if err != nil {
		return "", false, err
	}

	if strings.ToLower(email) != strings.ToLower(gotEmail) {
		return "", false, fmt.Errorf("queried for '%s', got back '%s'", email, gotEmail)
	}

	return armoredPublicKey, true, nil
}

// GetArmoredPublicKeyForFingerprint returns an ASCII-armored public key for the given fingerprint,
// regardless of whether the email addresses in the key have been verified.
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

// CreateVerification creates an email_verification for the given email address.
// `email` is the exact (not canonicalized) email address we're going to send the email to
// `fingerprint` is the fingerprint of the public key to link this email to
// `userAgent` is from the upsert request (probably Fluidkeys)
// `ipAddress` is the IP of the client that made the upsert request
func CreateVerification(
	txn *sql.Tx,
	email string,
	fp fpr.Fingerprint,
	userAgent string,
	ipAddress string,
	now time.Time,
) (*uuid.UUID, error) {

	secretUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	keyID, found, err := getKeyIDForFingerprint(txn, fp)

	if err != nil {
		return nil, err
	} else if !found {
		return nil, fmt.Errorf("no key found for fingerprint")
	}

	createdAt := now
	validUntil := createdAt.Add(time.Duration(15) * time.Minute)

	query := `INSERT INTO email_verifications (
                      created_at,
		      valid_until,
                      secret_uuid,
                      key_id,
                      key_fingerprint,
                      email_sent_to,
		      upsert_user_agent,
		      upsert_ip_address
		  )
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = transactionOrDatabase(txn).Exec(
		query, createdAt, validUntil, secretUUID, keyID, dbFormat(fp), email,
		userAgent, ipAddress,
	)
	return &secretUUID, err
}

// MarkVerificationAsVerified sets the user agent and IP address from the verifying HTTP request.
// Typically this is a browser from someone opening a link in their email.
func MarkVerificationAsVerified(txn *sql.Tx, secretUUID uuid.UUID,
	userAgent string, ipAddress string) error {

	query := `UPDATE email_verifications
		         SET (verify_user_agent, verify_ip_address) = ($2, $3)
			 WHERE secret_uuid=$1`

	_, err := txn.Exec(query, secretUUID, userAgent, ipAddress)
	return err
}

// GetVerification returns the email and fingerprint of a currently-active email_verification
// for the given secret UUID token.
func GetVerification(txn *sql.Tx, secretUUID uuid.UUID) (string, *fpr.Fingerprint, error) {
	query := `SELECT email_sent_to, key_fingerprint
                  FROM email_verifications
                  WHERE secret_uuid=$1
                  AND valid_until > now()`
	var email string
	var fingerprintString string

	err := txn.QueryRow(query, secretUUID).Scan(&email, &fingerprintString)
	if err == sql.ErrNoRows {
		return "", nil, fmt.Errorf("no such verification token '%s'", secretUUID)
	} else if err != nil {
		return "", nil, err
	}

	fingerprint, err := parseDbFormat(fingerprintString)
	if err != nil {
		return "", nil, fmt.Errorf("error parsing fingerprint '%s': %v",
			fingerprintString, err)
	}
	return email, &fingerprint, nil
}

// HasActiveVerificationForEmail returns whether we recently sent a
// verification email to the given email address, and if that verification
// is still valid, e.g. not expired
func HasActiveVerificationForEmail(txn *sql.Tx, email string) (bool, error) {
	query := `SELECT COUNT(*)
	          FROM email_verifications
	          WHERE email_sent_to=$1
		  AND valid_until > now()`

	var count int
	err := transactionOrDatabase(txn).QueryRow(query, email).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func getKeyIDForFingerprint(txn *sql.Tx, fingerprint fpr.Fingerprint) (keyID int64, found bool, err error) {
	query := `SELECT keys.id FROM keys WHERE fingerprint=$1`

	err = transactionOrDatabase(txn).QueryRow(query, dbFormat(fingerprint)).Scan(&keyID)
	if err == sql.ErrNoRows {
		return 0, false, nil // return found=false without an error

	} else if err != nil {
		return 0, false, err
	}

	return keyID, true, nil
}

// CreateSecret stores the armoredEncryptedSecret (which must be encrypted to
// the given `recipientFingerprint`) against the recipient public key.
func CreateSecret(recipientFingerprint fpr.Fingerprint, armoredEncryptedSecret string, now time.Time) (*uuid.UUID, error) {
	secretUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	keyID, found, err := getKeyIDForFingerprint(nil, recipientFingerprint)

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
		keyID,
		secretUUID,
		createdAt,
		armoredEncryptedSecret,
	)
	if err != nil {
		return nil, err
	}
	return &secretUUID, nil
}

// GetSecrets returns a slice of secrets for the given public key fingerprint
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

// DeleteSecret deletes the given secret (by UUID) if the recipientFingerprint matches the secret,
// or returns an error if not.
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

// VerifySingleUseNumberNotStored returns an error if the given singleUseUUID already exists in
// the database
func VerifySingleUseNumberNotStored(singleUseUUID uuid.UUID) error {
	query := `SELECT COUNT(uuid) FROM single_use_uuids WHERE uuid=$1`

	var count int
	err := db.QueryRow(query, singleUseUUID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return fmt.Errorf("single use UUID already used")
	}

	return nil
}

// StoreSingleUseNumber saves the given singleUseUUID to the database with the
// given now time.
// txn is a database transaction, or nil to run outside of a transaction
func StoreSingleUseNumber(txn *sql.Tx, singleUseUUID uuid.UUID, now time.Time) error {
	query := `INSERT INTO single_use_uuids (uuid, created_at)
	          VALUES ($1, $2)`

	_, err := transactionOrDatabase(txn).Exec(query, singleUseUUID, now)
	return err
}

// MustReadDatabaseURL returns the value of DATABASE_URL from the environment or panics if it
// wasn't found
func MustReadDatabaseURL() string {
	databaseURL, present := os.LookupEnv("DATABASE_URL")

	if !present {
		panic("Missing DATABASE_URL, it should be e.g. " +
			"postgres://vagrant:password@localhost:5432/vagrant")
	}
	return databaseURL
}

// Migrate runs all the database migration queries (create table etc)
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

// DropAllTheTables drops all the tables in the database. It's intendeded only for use in
// development, so before doing anything it checks that the current database is called
// `fkapi_test` or `travis`
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
		"single_use_uuids",
		"email_verifications",
		"email_key_link",
		"secrets",
		"keys",
		"teams",
	}

	for _, table := range tablesToDrop {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table)
		if err != nil {
			return fmt.Errorf("Error dropping table %s: %v", table, err)
		}
	}
	return nil
}

func transactionOrDatabase(txn *sql.Tx) txDbInterface {
	if txn != nil {
		return txn
	}
	return db
}

// txDbInterface allows a *sql.DB and a *sql.Tx to be used interchangeably
type txDbInterface interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

func dbFormat(fingerprint fpr.Fingerprint) string {
	return fmt.Sprintf("4:%s", fingerprint.Hex())
}

// returns a fingerprint.Fingerprint from e.g '4:'
func parseDbFormat(fingerprint string) (fpr.Fingerprint, error) {
	return fpr.Parse(fingerprint[2:])
}

type secret struct {
	ArmoredEncryptedSecret string
	SecretUUID             string
	CreatedAt              time.Time
}
