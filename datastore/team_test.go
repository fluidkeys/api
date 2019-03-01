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

func TestGetRequestToJoinTeam(t *testing.T) {
	now := time.Date(2019, 6, 19, 16, 35, 41, 0, time.UTC)

	t.Run("with existing request for team and email", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		fingerprint := fpr.MustParse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

		createdUUID, err := CreateRequestToJoinTeam(
			nil, testUUID, "test@example.com", fingerprint, now)
		assert.NoError(t, err)

		got, err := GetRequestToJoinTeam(nil, testUUID, "test@example.com")
		assert.NoError(t, err)

		assert.Equal(t, createdUUID.String(), got.UUID.String())
		assert.Equal(t, "test@example.com", got.Email)
		assert.Equal(t, fingerprint, got.Fingerprint)

		if !now.Equal(got.CreatedAt) {
			t.Fatalf("expected CreatedAt `%v`, got `%v`", now, got.CreatedAt)
		}
	})

	t.Run("with non existent team", func(t *testing.T) {
		_, err := GetRequestToJoinTeam(nil, testUUID, "test@example.com")
		assert.GotError(t, err)
		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("with matching team but no email", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		_, err := GetRequestToJoinTeam(nil, testUUID, "no-such-email@example.com")
		assert.GotError(t, err)
		assert.Equal(t, ErrNotFound, err)
	})
}

func TestGetRequestsToJoinTeam(t *testing.T) {
	now := time.Date(2019, 6, 19, 16, 35, 41, 0, time.UTC)

	t.Run("with existing request for team and email", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		fingerprint := fpr.MustParse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

		createdUUID1, err := CreateRequestToJoinTeam(
			nil, testUUID, "test@example.com", fingerprint, now)
		assert.NoError(t, err)

		fingerprint2 := fpr.MustParse("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		createdUUID2, err := CreateRequestToJoinTeam(
			nil, testUUID, "test2@example.com", fingerprint2, now)
		assert.NoError(t, err)

		got, err := GetRequestsToJoinTeam(nil, testUUID)
		assert.NoError(t, err)

		assert.Equal(t, 2, len(got))

		assert.Equal(t, createdUUID1.String(), got[0].UUID.String())
		assert.Equal(t, "test@example.com", got[0].Email)
		assert.Equal(t, fingerprint, got[0].Fingerprint)

		assert.Equal(t, createdUUID2.String(), got[1].UUID.String())
		assert.Equal(t, "test2@example.com", got[1].Email)
		assert.Equal(t, fingerprint2, got[1].Fingerprint)
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
