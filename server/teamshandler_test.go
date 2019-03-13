package server

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

func makeArmoredDetachedSignature(dataToSign []byte, privateKey *pgpkey.PgpKey) (string, error) {
	outputBuf := bytes.NewBuffer(nil)
	entity := privateKey.Entity

	err := openpgp.ArmoredDetachSign(outputBuf, &entity, bytes.NewReader(dataToSign), nil)
	if err != nil {
		return "", err
	}
	return outputBuf.String(), nil
}

func TestCreateTeamHandler(t *testing.T) {

	unlockedKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
		exampledata.ExamplePrivateKey4, "test4")
	signerFingerprint := unlockedKey.Fingerprint()

	assert.NoError(t, err)

	duplicateUUID, err := uuid.NewV4() // this is used to test the duplicated case
	assert.NoError(t, err)

	goodUUID, err := uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")
	assert.NoError(t, err)

	goodRoster := `
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true

[[person]]
email = "b@example.com"
fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
is_admin = false
`

	goodSignature, err := makeArmoredDetachedSignature([]byte(goodRoster), unlockedKey)
	assert.NoError(t, err)

	setup := func() {
		assert.NoError(t,
			datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))

		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4,
			),
		)

	}

	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)

		_, err = datastore.DeleteTeam(nil, goodUUID)
		assert.NoError(t, err)

		_, err = datastore.DeleteTeam(nil, duplicateUUID)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("creates team from valid roster and signature", func(t *testing.T) {
		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)

		t.Run("returns HTTP 201", func(t *testing.T) {
			assertStatusCode(t, http.StatusCreated, response.Code)
		})

		t.Run("adds valid database row", func(t *testing.T) {
			team, err := datastore.GetTeam(nil, goodUUID)
			assert.NoError(t, err)

			assert.Equal(t, goodUUID, team.UUID)
			assert.Equal(t, goodRoster, team.Roster)
			assert.Equal(t, goodSignature, team.RosterSignature)

			if now := time.Now(); team.CreatedAt.Sub(now) > time.Duration(5)*time.Second {
				t.Fatalf("expected team.CreatedAt to be within 5s of now (%s), got %s",
					now, team.CreatedAt)
			}
		})
	})

	t.Run("request doesn't contain signer fingerprint in auth header", func(t *testing.T) {
		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPIWithJSON(
			t, "POST", "/v1/teams", requestData, nil) // nil -> unauthenticated
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t,
			response.Body,
			"missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	})

	testEndpointRejectsBadJSON(t, "POST", "/v1/teams", nil)

	t.Run("missing json field", func(t *testing.T) {
		t.Run("teamRoster", func(t *testing.T) {
			requestData := v1structs.UpsertTeamRequest{
				ArmoredDetachedSignature: goodSignature,
			}

			response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)
			assertStatusCode(t, http.StatusBadRequest, response.Code)
			assertHasJSONErrorDetail(t, response.Body, "missing teamRoster")
		})

		t.Run("armoredDetachedSignature", func(t *testing.T) {
			requestData := v1structs.UpsertTeamRequest{
				TeamRoster: goodRoster,
			}

			response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)
			assertStatusCode(t, http.StatusBadRequest, response.Code)
			assertHasJSONErrorDetail(t, response.Body, "missing armoredDetachedSignature")
		})
	})

	t.Run("mismatch between signer fingerprint and long keyID in signature", func(t *testing.T) {
		mismatchedFingerprint := exampledata.ExampleFingerprint2

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(nil, "test2@example.com", mismatchedFingerprint))

		assert.NoError(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &mismatchedFingerprint)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"signature verification failed")

		_, err := datastore.DeletePublicKey(mismatchedFingerprint)
		assert.NoError(t, err)
	})

	t.Run("dont have public key that signed the roster", func(t *testing.T) {
		keyNotInAPI, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
			exampledata.ExamplePrivateKey3, "test3")
		fingerprintNotInAPI := keyNotInAPI.Fingerprint()
		assert.NoError(t, err)

		signature, err := makeArmoredDetachedSignature([]byte(goodRoster), keyNotInAPI)
		assert.NoError(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: signature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &fingerprintNotInAPI)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"public key that signed the roster has not been uploaded")
	})

	t.Run("roster signature invalid", func(t *testing.T) {
		modifiedRoster := goodRoster + "\n# roster that's been modified"

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               modifiedRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body, "signature verification failed")
	})

	t.Run("invalid roster", func(t *testing.T) {

		emailAddressTwice := `
uuid = "972dce6a-3532-11e9-b8df-f32e04ceb372"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true

[[person]]
email = "test4@example.com"
fingerprint = "BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB"
is_admin = false
`

		fingerprintTwice := `
uuid = "9ca4a81e-3532-11e9-9145-a3dd42867f07"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true

[[person]]
email = "b@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = false
`

		signingKeyNotInRoster := `
uuid = "344672d2-35e8-11e9-ade3-93c56fb48f08"

[[person]]
email = "test4@example.com"
fingerprint = "AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA"
is_admin = true
`

		signingKeyNotAnAdmin := `
uuid = "344672d2-35e8-11e9-ade3-93c56fb48f08"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"  # <-- signing key
is_admin = false

[[person]]
email = "the-admin@example.com"
fingerprint = "AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA"
is_admin = true
`

		unverifiedEmailInRoster := `
uuid = "113ab4ba-35e8-11e9-8aa6-f721c118df12"

[[person]]
email = "unverified-email@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true
`

		invalidRosterTests := []struct {
			testName            string
			roster              string
			expectedErrorDetail string
		}{
			{
				testName:            "team UUID is empty",
				roster:              "uuid = \"\"\n\n",
				expectedErrorDetail: "error in toml.DecodeReader: uuid: incorrect UUID length: ",
			},
			{
				testName:            "team UUID is all zeroes",
				roster:              "uuid = \"00000000-0000-0000-0000-000000000000\"\n\n",
				expectedErrorDetail: "invalid roster: invalid UUID",
			},
			{
				testName:            "email address appears twice",
				roster:              emailAddressTwice,
				expectedErrorDetail: "email listed more than once: test4@example.com",
			},
			{
				testName: "fingerprint appears twice",
				roster:   fingerprintTwice,
				expectedErrorDetail: "fingerprint listed more than once: BB3C 44BF 188D 56E6 " +
					"35F4  A092 F73D 2F05 33D7 F9D6",
			},
			{
				testName:            "signing key's fingerprint missing from roster",
				roster:              signingKeyNotInRoster,
				expectedErrorDetail: "signing key isn't listed in roster as a team admin",
			},
			{
				testName:            "signing key listed in roster but not an admin",
				roster:              signingKeyNotAnAdmin,
				expectedErrorDetail: "signing key isn't listed in roster as a team admin",
			},
			{
				testName:            "signing key's linked email in roster is unverified",
				roster:              unverifiedEmailInRoster,
				expectedErrorDetail: "signing key's email listed in roster is unverified",
			},
		}

		for _, test := range invalidRosterTests {
			t.Run(test.testName, func(t *testing.T) {

				signature, err := makeArmoredDetachedSignature([]byte(test.roster), unlockedKey)
				assert.NoError(t, err)

				requestData := v1structs.UpsertTeamRequest{
					TeamRoster:               test.roster,
					ArmoredDetachedSignature: signature,
				}

				response := callAPIWithJSON(
					t, "POST", "/v1/teams", requestData, &signerFingerprint)
				assertStatusCode(t, http.StatusBadRequest, response.Code)
				assertHasJSONErrorDetail(t, response.Body, test.expectedErrorDetail)
			})
		}

	})

	t.Run("reject update if team uuid already exists", func(t *testing.T) {
		duplicatedRoster := `
uuid = "` + duplicateUUID.String() + `"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true

[[person]]
email = "b@example.com"
fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
is_admin = false
`

		signature, err := makeArmoredDetachedSignature([]byte(duplicatedRoster), unlockedKey)
		assert.NoError(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               duplicatedRoster,
			ArmoredDetachedSignature: signature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)
		assertStatusCode(t, http.StatusCreated, response.Code)

		response = callAPIWithJSON(t, "POST", "/v1/teams", requestData, &signerFingerprint)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body, fmt.Sprintf("team with UUID %s already exists", duplicateUUID))
	})
}

func TestGetTeamHandler(t *testing.T) {
	now := time.Date(2019, 2, 28, 16, 35, 45, 0, time.UTC)
	exampleTeam := datastore.Team{
		UUID:            uuid.Must(uuid.FromString("aee4b386-3b52-11e9-a620-2381a199e2c8")),
		Roster:          "name = \"Example Team\"",
		RosterSignature: "",
		CreatedAt:       now,
	}

	setup := func() {
		assert.NoError(t, datastore.CreateTeam(nil, exampleTeam))
	}

	teardown := func() {
		_, err := datastore.DeleteTeam(nil, exampleTeam.UUID)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("for existing team", func(t *testing.T) {
		mockResponse := callAPI(t, "GET", "/v1/team/aee4b386-3b52-11e9-a620-2381a199e2c8", nil)

		t.Run("status code 200", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, mockResponse.Code)
		})

		t.Run("response has JSON content type", func(t *testing.T) {
			// TODO: check server returned content-type: application/json (and elsewhere!)
		})

		t.Run("response body has name in JSON", func(t *testing.T) {
			expected := "{\n    \"name\": \"Example Team\"\n}"
			got := mockResponse.Body.String()

			if got != expected {
				t.Errorf("unexpected body, expected `%v`, got `%v`", expected, got)
			}
		})
	})

	t.Run("for non existent team", func(t *testing.T) {
		// this UUID doesn't exist
		mockResponse := callAPI(t, "GET", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810", nil)

		t.Run("status code 404", func(t *testing.T) {
			assertStatusCode(t, http.StatusNotFound, mockResponse.Code)
		})
	})

	t.Run("for a team with a unparseable roster", func(t *testing.T) {
		badRosterTeam := datastore.Team{
			UUID:      uuid.Must(uuid.FromString("e9e6ab6e-3b67-11e9-a57c-8f865d47e520")),
			Roster:    "broken roster, no team name",
			CreatedAt: now,
		}

		assert.NoError(t, datastore.CreateTeam(nil, badRosterTeam))
		defer func() {
			datastore.DeleteTeam(nil, badRosterTeam.UUID)
		}()

		mockResponse := callAPI(t, "GET", "/v1/team/"+badRosterTeam.UUID.String(), nil)

		t.Run("status code 500", func(t *testing.T) {
			assertStatusCode(t, http.StatusInternalServerError, mockResponse.Code)
		})

		t.Run("error detail explains roster problem", func(t *testing.T) {
			assertHasJSONErrorDetail(t,
				mockResponse.Body,
				"failed to parse name from team roster")
		})
	})
}

func TestCreateRequestToJoinTeamHandler(t *testing.T) {
	now := time.Date(2019, 2, 28, 16, 35, 45, 0, time.UTC)
	exampleTeam := datastore.Team{
		UUID:            uuid.Must(uuid.FromString("aee4b386-3b52-11e9-a620-2381a199e2c8")),
		Roster:          "name = \"Example Team\"",
		RosterSignature: "",
		CreatedAt:       now,
	}

	setup := func() {
		assert.NoError(t, datastore.CreateTeam(nil, exampleTeam))

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4,
			))
	}

	teardown := func() {
		_, err := datastore.DeleteTeam(nil, exampleTeam.UUID)
		assert.NoError(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("create a request to join a team", func(t *testing.T) {
		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "test4@example.com",
		}

		mockResponse := callAPIWithJSON(t,
			"POST", "/v1/team/aee4b386-3b52-11e9-a620-2381a199e2c8/requests-to-join",
			requestData, &exampledata.ExampleFingerprint4)

		t.Run("status code 201 created", func(t *testing.T) {
			assertStatusCode(t, http.StatusCreated, mockResponse.Code)
		})
	})

	testEndpointRejectsBadJSON(t,
		"POST", "/v1/team/aee4b386-3b52-11e9-a620-2381a199e2c8/requests-to-join",
		&exampledata.ExampleFingerprint4)

	testEndpointRejectsUnauthenticated(t,
		"POST", "/v1/team/aee4b386-3b52-11e9-a620-2381a199e2c8/requests-to-join",
		v1structs.RequestToJoinTeamRequest{})

	t.Run("for non existent team", func(t *testing.T) {
		mockResponse := callAPI(t,
			// this team UUID doesn't exist
			"POST", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810/requests-to-join", nil)

		t.Run("status code 400 bad request", func(t *testing.T) {
			assertStatusCode(t, http.StatusBadRequest, mockResponse.Code)
		})
	})

	t.Run("missing teamEmail", func(t *testing.T) {
		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "",
		}

		mockResponse := callAPIWithJSON(t,
			"POST", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810/requests-to-join",
			requestData, &exampledata.ExampleFingerprint4)

		t.Run("status code 400 bad request", func(t *testing.T) {
			assertStatusCode(t, http.StatusBadRequest, mockResponse.Code)
		})

		t.Run("with good error message", func(t *testing.T) {
			assertHasJSONErrorDetail(t, mockResponse.Body, "missing teamEmail")
		})
	})

	t.Run("existing {team, email}, but different fingerprint should error", func(t *testing.T) {
		team := datastore.Team{
			UUID:            uuid.Must(uuid.NewV4()),
			Roster:          "name = \"Example Team\"",
			RosterSignature: "",
			CreatedAt:       now,
		}
		assert.NoError(t, datastore.CreateTeam(nil, team))
		defer func() {
			_, err := datastore.DeleteTeam(nil, team.UUID)
			assert.NoError(t, err)
		}()

		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "conflicting-example@example.com",
		}

		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "conflicting-example@example.com", exampledata.ExampleFingerprint4,
			))

		firstResponse := callAPIWithJSON(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", team.UUID),
			requestData, &exampledata.ExampleFingerprint4)

		assertStatusCode(t, http.StatusCreated, firstResponse.Code) // first request succeeds

		// insert exmaple key 2 as a conflicting key but with the same email

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "conflicting-example@example.com", exampledata.ExampleFingerprint2,
			))

		secondResponse := callAPIWithJSON(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", team.UUID),
			// same {team, email}, *different* fingerprint
			requestData, &exampledata.ExampleFingerprint2,
		)

		t.Run("returns http 409", func(t *testing.T) {
			assertStatusCode(t, http.StatusConflict, secondResponse.Code)
		})

		t.Run("with good error message", func(t *testing.T) {
			assertHasJSONErrorDetail(t, secondResponse.Body,
				"got existing request for conflicting-example@example.com to join that team "+
					"with a different fingerprint")
		})

		datastore.DeletePublicKey(exampledata.ExampleFingerprint2)
	})

	t.Run("existing {team, email, fingerprint} request should fail", func(t *testing.T) {
		team := datastore.Team{
			UUID:            uuid.Must(uuid.NewV4()),
			Roster:          "name = \"Example Team\"",
			RosterSignature: "",
			CreatedAt:       now,
		}
		assert.NoError(t, datastore.CreateTeam(nil, team))
		defer func() {
			_, err := datastore.DeleteTeam(nil, team.UUID)
			assert.NoError(t, err)
		}()

		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "test4@example.com",
		}

		firstResponse := callAPIWithJSON(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", team.UUID),
			requestData, &exampledata.ExampleFingerprint4)

		if firstResponse.Code != http.StatusCreated {
			t.Fatalf("failed to create team join request, got http %d", firstResponse.Code)
		}

		secondResponse := callAPIWithJSON(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", team.UUID),
			// same fingerprint as previous request: should succeed
			requestData, &exampledata.ExampleFingerprint4)

		t.Run("returns http 409 conflict", func(t *testing.T) {
			assertStatusCode(t, http.StatusConflict, secondResponse.Code)
		})

		t.Run("with good error message", func(t *testing.T) {
			assertHasJSONErrorDetail(t, secondResponse.Body,
				"already got request to join team with that email and fingerprint")
		})
	})
}
