package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

func TestListRequestsToJoinTeamHandler(t *testing.T) {

	teamUUID, err := uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")
	assert.NoError(t, err)

	goodRoster := `
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
`
	unlockedKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
		exampledata.ExamplePrivateKey4, "test4")

	now := time.Date(2019, 2, 10, 16, 35, 45, 0, time.UTC)

	goodSignature, err := unlockedKey.MakeArmoredDetachedSignature([]byte(goodRoster))
	assert.NoError(t, err)

	goodTeam := datastore.Team{
		UUID:            teamUUID,
		Roster:          goodRoster,
		RosterSignature: goodSignature,
		CreatedAt:       now,
	}

	setup := func() {
		assert.NoError(t,
			datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))

		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4,
			),
		)

		assert.NoError(t,
			datastore.CreateTeam(nil, goodTeam),
		)
	}

	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)

		_, err = datastore.DeleteTeam(nil, teamUUID)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("lists requests from valid fingerprint", func(t *testing.T) {
		requestToJoinUUID, err := datastore.CreateRequestToJoinTeam(
			nil,
			teamUUID,
			"request@example.com",
			fingerprint.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB"),
			now,
		)
		assert.NoError(t, err)

		response := callAPI(
			t,
			"GET",
			fmt.Sprintf("/v1/team/%s/requests-to-join", teamUUID),
			&exampledata.ExampleFingerprint4,
		)

		t.Run("status code 200", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("response has JSON content type", func(t *testing.T) {
			// TODO: check server returned content-type: application/json (and elsewhere!)
		})

		t.Run("response body has requests JSON", func(t *testing.T) {
			expected := `{
    "requests": [
        {
            "uuid": "` + requestToJoinUUID.String() + `",
            "fingerprint": "OPENPGP4FPR:AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB",
            "email": "request@example.com"
        }
    ]
}`
			got := response.Body.String()

			if got != expected {
				t.Errorf("unexpected body, expected `%v`, got `%v`", expected, got)
			}
		})
	})

	testEndpointRejectsUnauthenticated(t,
		"GET", fmt.Sprintf("/v1/team/%s/requests-to-join", teamUUID), struct{}{})

	t.Run("mismatch between signer fingerprint and long keyID in signature", func(t *testing.T) {
		mismatchedFingerprint := exampledata.ExampleFingerprint2

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(nil, "test2@example.com", mismatchedFingerprint))

		assert.NoError(t, err)

		response := callAPI(
			t,
			"GET",
			fmt.Sprintf("/v1/team/%s/requests-to-join", teamUUID),
			&mismatchedFingerprint,
		)

		assertStatusCode(t, http.StatusForbidden, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"your key doesn't have access to list team join requests")

		_, err := datastore.DeletePublicKey(mismatchedFingerprint)
		assert.NoError(t, err)
	})

	t.Run("for a bad team UUID", func(t *testing.T) {
		mismatchedFingerprint := exampledata.ExampleFingerprint2

		response := callAPI(
			t,
			"GET",
			"/v1/team/foo/requests-to-join",
			&exampledata.ExampleFingerprint4,
		)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"uuid: incorrect UUID length: foo")

		_, err := datastore.DeletePublicKey(mismatchedFingerprint)
		assert.NoError(t, err)
	})

	t.Run("for a team that doesn't exist", func(t *testing.T) {
		mismatchedFingerprint := exampledata.ExampleFingerprint2

		response := callAPI(
			t,
			"GET",
			fmt.Sprintf("/v1/team/%s/requests-to-join", uuid.Must(uuid.NewV4())),
			&exampledata.ExampleFingerprint4,
		)

		assertStatusCode(t, http.StatusNotFound, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"team not found")

		_, err := datastore.DeletePublicKey(mismatchedFingerprint)
		assert.NoError(t, err)
	})

}
