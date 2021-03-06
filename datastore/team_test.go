package datastore

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

func TestUpsertTeam(t *testing.T) {
	team := Team{
		UUID:            uuid.Must(uuid.NewV4()),
		Roster:          "fake-roster",
		RosterSignature: "fake-signature",
		CreatedAt:       now,
	}

	t.Run("creates a team with no error", func(t *testing.T) {

		err := UpsertTeam(nil, team)
		assert.NoError(t, err)
	})

	t.Run("team roster can be updated", func(t *testing.T) {
		teamUUID := uuid.Must(uuid.NewV4())
		originalTeam := Team{
			UUID:            teamUUID,
			Roster:          "original-roster",
			RosterSignature: "original-signature",
			CreatedAt:       now,
		}

		updatedTeam := Team{
			UUID:            teamUUID,
			Roster:          "updated-roster",
			RosterSignature: "updated-signature",
			CreatedAt:       later, // CreatedAt should *not* change on update
		}
		err := UpsertTeam(nil, originalTeam)
		assert.NoError(t, err)

		err = UpsertTeam(nil, updatedTeam)
		assert.NoError(t, err)

		retrievedTeam, err := GetTeam(nil, teamUUID)
		assert.NoError(t, err)

		t.Run("roster has been updated", func(t *testing.T) {
			assert.Equal(t, updatedTeam.Roster, retrievedTeam.Roster)
		})

		t.Run("roster signature has been updated", func(t *testing.T) {
			assert.Equal(t, updatedTeam.RosterSignature, retrievedTeam.RosterSignature)
		})

		t.Run("CreatedAt remains unchanged", func(t *testing.T) {
			assert.Equal(t, true, originalTeam.CreatedAt.Equal(retrievedTeam.CreatedAt))
		})

	})
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

func TestDeleteRequestToJoinTeam(t *testing.T) {
	createTestTeam(t)
	requestUUID := createTestRequestToJoinTeam(t)

	t.Run("when request exists", func(t *testing.T) {
		found, err := DeleteRequestToJoinTeam(nil, requestUUID)
		assert.NoError(t, err)
		assert.Equal(t, true, found)
	})

	t.Run("when request doesn't exist", func(t *testing.T) {
		found, err := DeleteRequestToJoinTeam(nil, uuid.Must(uuid.NewV4()))

		assert.NoError(t, err)
		assert.Equal(t, false, found)
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

	t.Run("with team existing but no requests", func(t *testing.T) {
		createTestTeam(t)
		defer deleteTestTeam(t)

		got, err := GetRequestsToJoinTeam(nil, testUUID)
		assert.NoError(t, err)

		assert.Equal(t, 0, len(got))
	})

	t.Run("with non-existent team, returns empty slice with no error", func(t *testing.T) {
		nonExistentTeamUUID := uuid.Must(uuid.NewV4())

		got, err := GetRequestsToJoinTeam(nil, nonExistentTeamUUID)
		assert.NoError(t, err)

		assert.Equal(t, 0, len(got))
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

	err := UpsertTeam(nil, team)
	assert.NoError(t, err)
}

func deleteTestTeam(t *testing.T) {
	t.Helper()
	_, err := DeleteTeam(nil, testUUID)
	assert.NoError(t, err)
}

func createTestRequestToJoinTeam(t *testing.T) uuid.UUID {
	t.Helper()
	requestUUID, err := CreateRequestToJoinTeam(nil,
		testUUID,
		"test4@example.com",
		exampledata.ExampleFingerprint4,
		later,
	)
	assert.NoError(t, err)

	return *requestUUID
}

var (
	now      = time.Date(2018, 6, 15, 16, 30, 0, 0, time.UTC)
	later    = now.Add(time.Duration(1) + time.Hour)
	testUUID = uuid.Must(uuid.NewV4())
)
