package datastore

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/gofrs/uuid"
)

func TestLoadUserProfile(t *testing.T) {
	deleteKeysAndUserProfiles(t)

	t.Run("loads existing user profile", func(t *testing.T) {
		err := UpsertPublicKey(nil, exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		keyID, err := getKeyID(nil, exampledata.ExampleFingerprint2)
		assert.NoError(t, err)

		_, err = createUserProfile(nil, keyID)
		assert.NoError(t, err)

		profile, err := loadUserProfile(nil, keyID)
		assert.NoError(t, err)

		if profile == nil {
			t.Fatalf("got profile=nil")
		}
	})

	t.Run("returns error if no such key exists", func(t *testing.T) {
		_, err := db.Exec("DELETE FROM keys")
		assert.NoError(t, err)

		nonExistentKeyID := 0
		_, err = loadUserProfile(nil, nonExistentKeyID)

		assert.GotError(t, err)
		assert.Equal(t, fmt.Errorf("no such key with id 0"), err)
	})

	t.Run("creates new profile if one doesn't exist already", func(t *testing.T) {
		// load the key, but delete the all profiles
		err := UpsertPublicKey(nil, exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		_, err = db.Exec("DELETE FROM user_profiles")
		assert.NoError(t, err)

		keyID, err := getKeyID(nil, exampledata.ExampleFingerprint2)
		assert.NoError(t, err)

		loadedProfile, err := loadUserProfile(nil, keyID)
		assert.NoError(t, err)

		// these should now be a user profile
		var retrievedUUID uuid.UUID
		err = db.QueryRow("SELECT uuid FROM user_profiles").Scan(&retrievedUUID)
		assert.NoError(t, err)

		assert.Equal(t, loadedProfile.UUID, retrievedUUID)
	})
}

func TestCreateUserProfile(t *testing.T) {
	t.Run("creates a user profile", func(t *testing.T) {
		deleteKeysAndUserProfiles(t)

		err := UpsertPublicKey(nil, exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		var keyID int
		err = db.QueryRow(
			"SELECT keys.id FROM keys WHERE fingerprint=$1",
			dbFormat(exampledata.ExampleFingerprint2)).Scan(&keyID)
		assert.NoError(t, err)

		gotProfile, err := createUserProfile(nil, keyID)
		assert.NoError(t, err)

		t.Run("profile returned from createUserProfile has expected KeyID", func(t *testing.T) {
			assert.Equal(t, keyID, gotProfile.KeyID)
		})

		t.Run("profile read back from DB matches that returned from createUserProfile", func(t *testing.T) {
			var retrievedUUID uuid.UUID
			var retrievedKeyID int

			err = db.QueryRow("SELECT uuid, key_id FROM user_profiles").Scan(&retrievedUUID, &retrievedKeyID)
			assert.NoError(t, err)

			assert.Equal(t, gotProfile.UUID, retrievedUUID)
			assert.Equal(t, gotProfile.KeyID, retrievedKeyID)
		})
	})
}

func deleteKeysAndUserProfiles(t *testing.T) {
	t.Helper()

	_, err := db.Exec("DELETE FROM keys")
	assert.NoError(t, err)

	_, err = db.Exec("DELETE FROM user_profiles")
	assert.NoError(t, err)
}
