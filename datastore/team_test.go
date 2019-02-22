package datastore

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
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
	assert.ErrorIsNil(t, err)
}

func TestGetTeam(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		team, err := GetTeam(nil, testUUID)
		assert.ErrorIsNil(t, err)
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
		assert.ErrorIsNotNil(t, err)
		if team != nil {
			t.Fatalf("expected team=nil, got %v", team)
		}
	})
}

func TestTeamExists(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		exists, err := TeamExists(nil, testUUID)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, true, exists)
	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		deleteTestTeam(t)

		exists, err := TeamExists(nil, testUUID)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, false, exists)
	})
}

func TestDeleteTeam(t *testing.T) {
	t.Run("when team exists", func(t *testing.T) {
		createTestTeam(t)

		found, err := DeleteTeam(nil, testUUID)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, true, found)

	})

	t.Run("when team doesn't exist", func(t *testing.T) {
		deleteTestTeam(t)

		found, err := DeleteTeam(nil, testUUID)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, false, found)
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
	assert.ErrorIsNil(t, err)
}

func deleteTestTeam(t *testing.T) {
	t.Helper()
	_, err := DeleteTeam(nil, testUUID)
	assert.ErrorIsNil(t, err)
}

var (
	now      = time.Date(2018, 6, 15, 16, 30, 0, 0, time.UTC)
	testUUID = uuid.Must(uuid.NewV4())
)
