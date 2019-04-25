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

func TestRecordSentEmail(t *testing.T) {
	profile := createKeyAndUserProfile(t)
	defer func() {
		_, err := db.Exec("DELETE FROM user_profiles")
		assert.NoError(t, err)
	}()
	profileUUID := profile.UUID

	now := time.Date(2019, 6, 12, 16, 35, 5, 0, time.UTC)

	t.Run("creates correct database row", func(t *testing.T) {
		deleteEmailsSent(t)

		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, now))

		var retrievedTemplateID string
		var retrievedUserProfileUUID uuid.UUID
		var retrievedSentAt time.Time

		err := db.QueryRow(
			`SELECT email_template_id, user_profile_uuid, sent_at FROM emails_sent`,
		).Scan(&retrievedTemplateID, &retrievedUserProfileUUID, &retrievedSentAt)
		assert.NoError(t, err)

		assert.Equal(t, "template_1", retrievedTemplateID)
		assert.Equal(t, profileUUID, retrievedUserProfileUUID)
		if !retrievedSentAt.Equal(now) {
			t.Fatalf("expected retrievedSentAt=%s, got %s", retrievedSentAt, now)
		}
	})

	t.Run("stores empty email template ID", func(t *testing.T) {
		deleteEmailsSent(t)

		assert.NoError(t, RecordSentEmail(nil, "", profileUUID, now))
	})

	t.Run("non-existent user profile UUID", func(t *testing.T) {
		nonExistentUUID := uuid.Must(uuid.NewV4())
		err := RecordSentEmail(nil, "template_1", nonExistentUUID, now)
		assert.Equal(t, fmt.Errorf("no such user profile with UUID %s", nonExistentUUID), err)
	})
}

func TestCanSendWithRateLimit(t *testing.T) {
	profile := createKeyAndUserProfile(t)
	defer func() {
		_, err := db.Exec("DELETE FROM user_profiles")
		assert.NoError(t, err)
	}()
	profileUUID := profile.UUID

	now := time.Date(2019, 6, 12, 16, 35, 5, 0, time.UTC)

	t.Run("when no matching email has ever been sent", func(t *testing.T) {
		deleteEmailsSent(t)
		rateLimit := time.Duration(1) * time.Hour
		allowed, err := CanSendWithRateLimit("template_1", profileUUID, &rateLimit, now)

		assert.NoError(t, err)
		assert.Equal(t, true, allowed)
	})

	t.Run("when an email was sent within rate limit (too recently)", func(t *testing.T) {
		deleteEmailsSent(t)

		tenMinutesAgo := now.Add(-time.Duration(10) * time.Minute)

		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, tenMinutesAgo))

		rateLimit := time.Duration(1) * time.Hour
		allowed, err := CanSendWithRateLimit("template_1", profileUUID, &rateLimit, now)
		assert.NoError(t, err)

		assert.Equal(t, false, allowed)
	})

	t.Run("when an email was sent before (OK to send another)", func(t *testing.T) {
		deleteEmailsSent(t)

		twoHoursAgo := now.Add(-time.Duration(2) * time.Hour)

		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, twoHoursAgo))

		rateLimit := time.Duration(1) * time.Hour
		allowed, err := CanSendWithRateLimit("template_1", profileUUID, &rateLimit, now)
		assert.NoError(t, err)

		assert.Equal(t, true, allowed)
	})

	t.Run("when no rate limit is given always return true", func(t *testing.T) {
		deleteEmailsSent(t)

		tenMinutesAgo := now.Add(-time.Duration(10) * time.Minute)

		assert.NoError(t, RecordSentEmail(nil, "template_1", profileUUID, tenMinutesAgo))

		var rateLimit *time.Duration // nil means "no rate limit"
		allowed, err := CanSendWithRateLimit("template_1", profileUUID, rateLimit, now)
		assert.NoError(t, err)

		assert.Equal(t, true, allowed)
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
