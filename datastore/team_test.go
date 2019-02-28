package datastore

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

func TestCreateTeam(t *testing.T) {
	team := Team{
		UUID:            uuid.Must(uuid.NewV4()),
		Roster:          "fake-roster",
		RosterSignature: "fake-signature",
		CreatedAt:       now,
	}

	err := CreateTeam(nil, team)
	assert.NoError(t, err)
}

func TestGetTeam(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		team, err := GetTeam(nil, testUUID)
		assert.NoError(t, err)
		if team == nil {
			t.Fatalf("expected team, got nil")
		}

		assert.Equal(t, team.UUID, testUUID)
		assert.Equal(t, team.Roster, "fake-roster")
		assert.Equal(t, team.RosterSignature, "fake-signature")
		if !team.CreatedAt.Equal(now) {
			t.Fatalf("expected %s, got %s", team.CreatedAt, now)
		}
	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		deleteTestTeam(t)

		team, err := GetTeam(nil, testUUID)
		assert.GotError(t, err)
		if team != nil {
			t.Fatalf("expected team=nil, got %v", team)
		}
	})
}

func TestTeamExists(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		exists, err := TeamExists(nil, testUUID)
		assert.NoError(t, err)
		assert.Equal(t, true, exists)
	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		deleteTestTeam(t)

		exists, err := TeamExists(nil, testUUID)
		assert.NoError(t, err)
		assert.Equal(t, false, exists)
	})
}

func TestDeleteTeam(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		found, err := DeleteTeam(nil, testUUID)
		assert.NoError(t, err)
		assert.Equal(t, true, found)

	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		deleteTestTeam(t)

		found, err := DeleteTeam(nil, testUUID)
		assert.NoError(t, err)
		assert.Equal(t, false, found)
	})
}

func TestCreateRequestToJoinTeam(t *testing.T) {
	t.Run("when team exists and request is OK", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		now := time.Now()

		_, err := CreateRequestToJoinTeam(
			nil,
			testUUID,
			"test@example.com",
			fpr.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB"),
			now,
		)
		assert.NoError(t, err)
	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		_, err := CreateRequestToJoinTeam(
			nil,
			uuid.Must(uuid.NewV4()), // no existent
			"test@example.com",
			fpr.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB"),
			now,
		)
		assert.GotError(t, err)
		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("existing (team, email), but different fingerprint should error", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		_, err := CreateRequestToJoinTeam(
			nil,
			testUUID,
			"conflicting-fingerprint@example.com",
			fpr.MustParse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			now,
		)
		assert.NoError(t, err)

		_, err = CreateRequestToJoinTeam(
			nil,
			testUUID,
			"conflicting-fingerprint@example.com",
			fpr.MustParse("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), // different fingerprint
			now,
		)
		assert.GotError(t, err)
	})

	t.Run("existing (team, email, fingerprint) request should silently succeed", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		firstUUID, err := CreateRequestToJoinTeam(
			nil, testUUID,
			"duplicate-request@example.com",
			fpr.MustParse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			now,
		)
		assert.NoError(t, err)

		secondUUID, err := CreateRequestToJoinTeam(
			nil, testUUID,
			"duplicate-request@example.com",
			fpr.MustParse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			now,
		)
		assert.NoError(t, err)
		assert.Equal(t, *firstUUID, *secondUUID) // return the UUID of the existing, identical req
	})
}

func createTestTeam(t *testing.T) {
	t.Helper()
	team := Team{
		UUID:            testUUID,
		Roster:          "fake-roster",
		RosterSignature: "fake-signature",
		CreatedAt:       now,
	}

	err := CreateTeam(nil, team)
	assert.NoError(t, err)
}

func deleteTestTeam(t *testing.T) {
	t.Helper()
	_, err := DeleteTeam(nil, testUUID)
	assert.NoError(t, err)
}

var (
	now      = time.Date(2018, 6, 15, 16, 30, 0, 0, time.UTC)
	testUUID = uuid.Must(uuid.NewV4())
)
