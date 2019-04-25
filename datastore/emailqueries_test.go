package datastore

import (
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/gofrs/uuid"
)

func TestGetTimeLastSent(t *testing.T) {
	profile := createKeyAndUserProfile(t)
	defer func() {
		_, err := db.Exec("DELETE FROM user_profiles")
		assert.NoError(t, err)
	}()

	profileUUID := profile.UUID

	now := time.Date(2019, 6, 12, 16, 35, 5, 0, time.UTC)
	earlier := now.Add(-time.Duration(10) * time.Minute)
	later := now.Add(time.Duration(10) * time.Minute)

	t.Run("returns correct time", func(t *testing.T) {
		deleteEmailsSent(t)

		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, earlier))
		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, later))
		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, now))

		gotTime, err := GetTimeLastSent(nil, "template_1", profileUUID)
		assert.NoError(t, err)

		if !later.Equal(*gotTime) {
			t.Fatalf("expected gotTime=%v, got %v", later, gotTime)
		}
	})

	t.Run("rejects empty email template ID", func(t *testing.T) {
		_, err := GetTimeLastSent(nil, "", profileUUID)
		assert.Equal(t, fmt.Errorf("invalid emailTemplateID: cannot be empty"), err)
	})

	t.Run("returns time=nil if never sent before", func(t *testing.T) {
		deleteEmailsSent(t)

		gotTime, err := GetTimeLastSent(nil, "template_1", profileUUID)
		assert.NoError(t, err)

		if gotTime != nil {
			t.Fatalf("expected gotTime=nil, got %v", gotTime)
		}
	})
}

func deleteEmailsSent(t *testing.T) {
	t.Helper()

	_, err := db.Exec("DELETE FROM emails_sent")
	assert.NoError(t, err)
}

func createKeyAndUserProfile(t *testing.T) *UserProfile {
	t.Helper()
	err := UpsertPublicKey(nil, exampledata.ExamplePublicKey2)
	assert.NoError(t, err)

	keyID, err := getKeyID(nil, exampledata.ExampleFingerprint2)
	assert.NoError(t, err)

	profile, err := createUserProfile(nil, keyID)
	assert.NoError(t, err)
	return profile
}
