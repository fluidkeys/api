package datastore

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
)

func TestMain(m *testing.M) {
	if testDatabaseURL, got := os.LookupEnv("TEST_DATABASE_URL"); got {
		Initialize(testDatabaseURL)
	} else {
		panic("TEST_DATABASE_URL not set")
	}

	err := Migrate()
	if err != nil {
		panic(fmt.Errorf("failed to migrate test database: %v", err))
	}

	code := m.Run()

	err = DropAllTheTables()
	if err != nil {
		panic(fmt.Errorf("failed to empty test database: %v", err))
	}

	os.Exit(code)
}

func TestEmailVerificationFunctions(t *testing.T) {

	email := "test@example.com"
	fingerprint := exampledata.ExampleFingerprint2

	err := UpsertPublicKey(nil, exampledata.ExamplePublicKey2)
	assert.NoError(t, err)

	verificationUUID, err := CreateVerification(
		nil,
		email,
		fingerprint,
		"fake user agent",
		"0.0.0.0",
		now,
	)
	assert.NoError(t, err)
	if verificationUUID == nil {
		t.Fatalf("got back nil verification UUID")
	}

	t.Run("read back verification from db", func(t *testing.T) {
		query := `SELECT
					created_at,
					valid_until,
					email_sent_to,
					key_fingerprint,
					upsert_user_agent,
					upsert_ip_address,
					verify_user_agent,
					verify_ip_address
				FROM email_verifications
				WHERE uuid=$1`

		var createdAt time.Time
		var validUntil time.Time
		var emailSentTo string
		var keyFingerprint string
		var upsertUserAgent *string
		var upsertIPAddress *string
		var verifyUserAgent *string
		var verifyIPAddress *string

		err := db.QueryRow(query, *verificationUUID).Scan(
			&createdAt,
			&validUntil,
			&emailSentTo,
			&keyFingerprint,
			&upsertUserAgent,
			&upsertIPAddress,
			&verifyUserAgent,
			&verifyIPAddress,
		)
		assert.NoError(t, err)

		assertEqualTime(t, now, createdAt)
		assertEqualTime(t, now.Add(time.Duration(15)*time.Minute), validUntil)
		assert.Equal(t, email, emailSentTo)
		assert.Equal(t, dbFormat(fingerprint), keyFingerprint)
		assert.Equal(t, "fake user agent", *upsertUserAgent)
		assert.Equal(t, "0.0.0.0", *upsertIPAddress)
		if verifyUserAgent != nil {
			t.Fatalf("expected verifyUserAgent=nil, got %v", verifyUserAgent)
		}
		if verifyIPAddress != nil {
			t.Fatalf("expected verifyIPAddress=nil, got %v", verifyIPAddress)
		}
	})

	t.Run("test GetVerification", func(t *testing.T) {
		verificationUUID, err := CreateVerification(
			nil,
			"test@example.com",
			exampledata.ExampleFingerprint2,
			"fake user agent",
			"0.0.0.0",
			now,
		)
		assert.NoError(t, err)

		email, fingerprint, err := GetVerification(nil, *verificationUUID, now)
		assert.NoError(t, err)

		assert.Equal(t, "test@example.com", email)
		assert.Equal(t, exampledata.ExampleFingerprint2, *fingerprint)
	})

	t.Run("test MarkVerificationAsVerified", func(t *testing.T) {
		err := MarkVerificationAsVerified(nil, *verificationUUID, "fake user agent 2", "1.1.1.1")
		assert.NoError(t, err)

		query := `SELECT
					verify_user_agent,
					verify_ip_address
				FROM email_verifications
				WHERE uuid=$1`

		var verifyUserAgent *string
		var verifyIPAddress *string

		err = db.QueryRow(query, *verificationUUID).Scan(
			&verifyUserAgent,
			&verifyIPAddress,
		)
		assert.NoError(t, err)

		assert.Equal(t, "fake user agent 2", *verifyUserAgent)
		assert.Equal(t, "1.1.1.1", *verifyIPAddress)
	})
}

func assertEqualTime(t *testing.T, expected time.Time, got time.Time) {
	t.Helper()
	if !expected.Equal(got) {
		t.Fatalf("times don't match, expected %v, got %v", expected, got)
	}
}

func TestLinkEmailToFingerprint(t *testing.T) {
	email := "test@example.com"
	fingerprint := exampledata.ExampleFingerprint2

	t.Run("test create", func(t *testing.T) {

		verificationUUID, err := CreateVerification(
			nil,
			email,
			fingerprint,
			"fake user agent",
			"0.0.0.0",
			now,
		)

		assert.NoError(t, err)

		err = MarkVerificationAsVerified(nil, *verificationUUID, "fake user agent 2", "1.1.1.1")
		assert.NoError(t, err)

		err = LinkEmailToFingerprint(nil, email, fingerprint)
		assert.NoError(t, err)

		t.Run("read back linked key ID for email address", func(t *testing.T) {
			var keyID int
			query := `SELECT id FROM keys WHERE fingerprint=$1`
			err = db.QueryRow(query, dbFormat(fingerprint)).Scan(&keyID)
			assert.NoError(t, err)

			query = `SELECT key_id
				FROM email_key_link
				WHERE email=$1`

			var readBackKeyID int

			err = db.QueryRow(query, email).Scan(&readBackKeyID)
			assert.NoError(t, err)

			assert.Equal(t, keyID, readBackKeyID)
		})

	})

	t.Run("test update can set key to a new key", func(t *testing.T) {
		updatedFingerprint := exampledata.ExampleFingerprint3

		err := UpsertPublicKey(nil, exampledata.ExamplePublicKey3)
		assert.NoError(t, err)

		err = LinkEmailToFingerprint(nil, email, updatedFingerprint)
		assert.NoError(t, err)

		t.Run("read back updated key ID for email address", func(t *testing.T) {
			var keyID int
			query := `SELECT id FROM keys WHERE fingerprint=$1`
			err = db.QueryRow(query, dbFormat(updatedFingerprint)).Scan(&keyID)
			assert.NoError(t, err)

			query = `SELECT key_id
				FROM email_key_link
				WHERE email=$1`

			var readBackKeyID int

			err = db.QueryRow(query, email).Scan(&readBackKeyID)
			assert.NoError(t, err)

			assert.Equal(t, keyID, readBackKeyID)
		})

	})

}
