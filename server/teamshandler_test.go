package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
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
version = 3

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
				nil, "test4@example.com", exampledata.ExampleFingerprint4, nil,
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

		response := callAPI(t, "POST", "/v1/teams", requestData, &signerFingerprint)

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

	t.Run("creates team from roster with missing version", func(t *testing.T) {
		rosterNoVersion := `
uuid = "0de4fe1e-7734-11e9-98db-c758e3a77a16"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true
`
		sigNoVersion, err := makeArmoredDetachedSignature([]byte(rosterNoVersion), unlockedKey)
		assert.NoError(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               rosterNoVersion,
			ArmoredDetachedSignature: sigNoVersion,
		}

		response := callAPI(t, "POST", "/v1/teams", requestData, &signerFingerprint)
		assertStatusCode(t, http.StatusCreated, response.Code)
	})

	t.Run("request doesn't contain signer fingerprint in auth header", func(t *testing.T) {
		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPI(
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

			response := callAPI(t, "POST", "/v1/teams", requestData, &signerFingerprint)
			assertStatusCode(t, http.StatusBadRequest, response.Code)
			assertHasJSONErrorDetail(t, response.Body, "missing teamRoster")
		})

		t.Run("armoredDetachedSignature", func(t *testing.T) {
			requestData := v1structs.UpsertTeamRequest{
				TeamRoster: goodRoster,
			}

			response := callAPI(t, "POST", "/v1/teams", requestData, &signerFingerprint)
			assertStatusCode(t, http.StatusBadRequest, response.Code)
			assertHasJSONErrorDetail(t, response.Body, "missing armoredDetachedSignature")
		})
	})

	t.Run("mismatch between signer fingerprint and long keyID in signature", func(t *testing.T) {
		mismatchedFingerprint := exampledata.ExampleFingerprint2

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(nil, "test2@example.com", mismatchedFingerprint, nil))

		assert.NoError(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPI(t, "POST", "/v1/teams", requestData, &mismatchedFingerprint)
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

		requestData := makeSignedRequest(t, goodRoster, keyNotInAPI)

		response := callAPI(t, "POST", "/v1/teams", requestData, &fingerprintNotInAPI)
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

		response := callAPI(t, "POST", "/v1/teams", requestData, &signerFingerprint)
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
				expectedErrorDetail: "error validating team: invalid roster: invalid UUID",
			},
			{
				testName: "email address appears twice",
				roster:   emailAddressTwice,
				expectedErrorDetail: "error validating team: email listed more than once: " +
					"test4@example.com",
			},
			{
				testName: "fingerprint appears twice",
				roster:   fingerprintTwice,
				expectedErrorDetail: "error validating team: fingerprint listed more than once: " +
					"BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6",
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

				requestData := makeSignedRequest(t, test.roster, unlockedKey)

				response := callAPI(
					t, "POST", "/v1/teams", requestData, &signerFingerprint)
				assertStatusCode(t, http.StatusBadRequest, response.Code)
				assertHasJSONErrorDetail(t, response.Body, test.expectedErrorDetail)
			})
		}

	})

	t.Run("update existing team", func(t *testing.T) {
		t.Run("with valid update request ", func(t *testing.T) {
			roster1 := `
				uuid = "74522e58-45be-11e9-b653-ab65bb61ab3b"
				name = "BEFORE"
				version = 1

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = true

				[[person]]
				email = "another@example.com"
				fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				is_admin = false`

			roster2 := `
				uuid = "74522e58-45be-11e9-b653-ab65bb61ab3b"
				name = "AFTER"
				version = 2

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = true

				[[person]]
				email = "another@example.com"
				fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"  # <-- different!
				is_admin = false`

			requestData1 := makeSignedRequest(t, roster1, unlockedKey)
			response1 := callAPI(t, "POST", "/v1/teams", requestData1, &signerFingerprint)
			assertStatusCode(t, http.StatusCreated, response1.Code)

			requestData2 := makeSignedRequest(t, roster2, unlockedKey)
			response2 := callAPI(t, "POST", "/v1/teams", requestData2, &signerFingerprint)
			assertStatusCode(t, http.StatusOK, response2.Code)

			retrievedTeam, err := loadExistingTeam(
				nil, uuid.Must(uuid.FromString("74522e58-45be-11e9-b653-ab65bb61ab3b")),
			)
			assert.NoError(t, err)

			t.Run("team name was updated", func(t *testing.T) {
				assert.Equal(t, "AFTER", retrievedTeam.Name)
			})

			t.Run("team members were updated", func(t *testing.T) {
				expectedPeople := []team.Person{
					{
						Email: "test4@example.com",
						Fingerprint: fpr.MustParse(
							"BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"),
						IsAdmin: true,
					},
					{
						Email:       "another@example.com",
						Fingerprint: fpr.MustParse("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
						IsAdmin:     false,
					},
				}
				assert.Equal(t, expectedPeople, retrievedTeam.People)
			})
		})

		t.Run("signer cannot demote themselves as admin", func(t *testing.T) {
			roster1 := `
				uuid = "6aa9b9b8-463e-11e9-8a5f-7753b9c9218c"
				name = "BEFORE"

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = true`

			roster2 := `
				uuid = "6aa9b9b8-463e-11e9-8a5f-7753b9c9218c"
				name = "AFTER"

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = false  # <-- demoted

				[[person]]
				# another person to ensure roster2 is still valid
				email = "another@example.com"
				fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
				is_admin = true`

			requestData1 := makeSignedRequest(t, roster1, unlockedKey)
			response1 := callAPI(t, "POST", "/v1/teams", requestData1, &signerFingerprint)
			assertStatusCode(t, http.StatusCreated, response1.Code)

			requestData2 := makeSignedRequest(t, roster2, unlockedKey)
			response2 := callAPI(t, "POST", "/v1/teams", requestData2, &signerFingerprint)
			assertStatusCode(t, http.StatusBadRequest, response2.Code)
			assertHasJSONErrorDetail(t,
				response2.Body, "signing key isn't listed in roster as a team admin",
			)
		})

		t.Run("reject if signer is not an admin in the existing team", func(t *testing.T) {
			roster1 := `
				uuid = "98f2c6ca-463e-11e9-8bac-43602efc043e"
				name = "BEFORE"

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = true

				[[person]]
				email = "test3@example.com"
				fingerprint = "7C18 DE4D E478 1356 8B24  3AC8 719B D63E F03B DC20"
				is_admin = false`

			roster2 := `
				uuid = "98f2c6ca-463e-11e9-8bac-43602efc043e"
				name = "AFTER"

				[[person]]
				email = "test4@example.com"
				fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
				is_admin = true

				[[person]]
				email = "test3@example.com"
				fingerprint = "7C18 DE4D E478 1356 8B24  3AC8 719B D63E F03B DC20"
				is_admin = true # <--- not allowed!`

			requestData1 := makeSignedRequest(t, roster1, unlockedKey)
			response1 := callAPI(t, "POST", "/v1/teams", requestData1, &signerFingerprint)
			assertStatusCode(t, http.StatusCreated, response1.Code)

			// now set up update request
			unauthorizedKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
				exampledata.ExamplePrivateKey3, "test3")
			assert.NoError(t, err)

			assert.NoError(t,
				datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey3))

			assert.NoError(t,
				datastore.LinkEmailToFingerprint(
					nil, "test3@example.com", exampledata.ExampleFingerprint3, nil,
				),
			)

			defer func() {
				datastore.DeletePublicKey(unauthorizedKey.Fingerprint())
			}()

			requestData2 := makeSignedRequest(t, roster2, unauthorizedKey)
			response2 := callAPI(
				t, "POST", "/v1/teams", requestData2, &exampledata.ExampleFingerprint3)
			assertStatusCode(t, http.StatusForbidden, response2.Code)
			assertHasJSONErrorDetail(t,
				response2.Body,
				"can't update team: the key signing the request is not a team admin",
			)
		})
	})

}

func makeSignedRequest(t *testing.T, roster string, privateKey *pgpkey.PgpKey) v1structs.UpsertTeamRequest {
	t.Helper()

	sig, err := makeArmoredDetachedSignature([]byte(roster), privateKey)
	assert.NoError(t, err)

	requestData := v1structs.UpsertTeamRequest{
		TeamRoster:               roster,
		ArmoredDetachedSignature: sig,
	}

	return requestData
}

func TestGetTeamHandler(t *testing.T) {
	now := time.Date(2019, 2, 28, 16, 35, 45, 0, time.UTC)
	exampleTeam := datastore.Team{
		UUID: uuid.Must(uuid.FromString("aee4b386-3b52-11e9-a620-2381a199e2c8")),
		Roster: `uuid = "aee4b386-3b52-11e9-a620-2381a199e2c8"
		name = "Example Team"

		[[person]]
			email = "test4@example.com"
			fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
			is_admin = true`,
		RosterSignature: "",
		CreatedAt:       now,
	}

	setup := func() {
		assert.NoError(t, datastore.UpsertTeam(nil, exampleTeam))
	}

	teardown := func() {
		_, err := datastore.DeleteTeam(nil, exampleTeam.UUID)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("for existing team", func(t *testing.T) {
		mockResponse := callAPI(t,
			"GET", "/v1/team/aee4b386-3b52-11e9-a620-2381a199e2c8", nil, nil)

		t.Run("status code 200", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, mockResponse.Code)
		})

		t.Run("response has json content type", func(t *testing.T) {
			assert.Equal(t, "application/json", mockResponse.Header().Get("content-type"))
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
		mockResponse := callAPI(t,
			"GET", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810", nil, nil)

		t.Run("status code 404", func(t *testing.T) {
			assertStatusCode(t, http.StatusNotFound, mockResponse.Code)
		})
	})

	t.Run("for a team with a unparseable roster", func(t *testing.T) {
		badRosterTeam := datastore.Team{
			UUID:            uuid.Must(uuid.NewV4()),
			Roster:          "broken roster, no team name",
			RosterSignature: "bad signature",
			CreatedAt:       now,
		}

		err := datastore.RunInTransaction(func(txn *sql.Tx) error {
			_, err := txn.Exec(
				"INSERT INTO teams (uuid, created_at) VALUES($1, $2)",
				badRosterTeam.UUID,
				badRosterTeam.CreatedAt,
			)
			if err != nil {
				return err
			}
			_, err = txn.Exec(
				`INSERT INTO roster_versions (
                    version,
				    team_uuid,
                    created_at,
                    roster,
                    roster_signature)
                 VALUES(1, $1, $2, $3, $4)`,
				badRosterTeam.UUID,
				badRosterTeam.CreatedAt,
				badRosterTeam.Roster,
				badRosterTeam.RosterSignature,
			)
			return err
		})
		assert.NoError(t, err)
		defer func() {
			datastore.DeleteTeam(nil, badRosterTeam.UUID)
		}()

		mockResponse := callAPI(t, "GET", "/v1/team/"+badRosterTeam.UUID.String(), nil, nil)

		t.Run("status code 500", func(t *testing.T) {
			assertStatusCode(t, http.StatusInternalServerError, mockResponse.Code)
		})

		t.Run("error detail explains roster problem", func(t *testing.T) {
			assertHasJSONErrorDetail(t,
				mockResponse.Body,
				"failed to parse team from roster stored in db: error in toml.DecodeReader: "+
					"Near line 1 (last key parsed 'broken'): expected key separator '=', but "+
					"got 'r' instead")
		})
	})
}

func createExampleTeam(t *testing.T, createdAt time.Time) datastore.Team {
	t.Helper()

	roster := `
uuid = "aee4b386-3b52-11e9-a620-2381a199e2c8"
name = "Example Team"
version = 1

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true`

	sig := ""

	team, err := team.Load(roster, sig)
	assert.NoError(t, err)

	dbTeam := datastore.Team{
		UUID:            team.UUID,
		Roster:          roster,
		RosterSignature: sig,
		CreatedAt:       createdAt,
	}
	return dbTeam
}

func TestCreateRequestToJoinTeamHandler(t *testing.T) {
	now := time.Date(2019, 2, 28, 16, 35, 45, 0, time.UTC)

	exampleTeam := createExampleTeam(t, now)

	setup := func() {
		assert.NoError(t, datastore.UpsertTeam(nil, exampleTeam))

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4, nil,
			))
	}

	teardown := func() {
		_, err := datastore.DeleteTeam(nil, exampleTeam.UUID)
		assert.NoError(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)
	}

	deleteRequests := func() {
		err := datastore.RunInTransaction(func(txn *sql.Tx) error {
			_, err := txn.Exec("DELETE FROM team_join_requests WHERE team_uuid=$1",
				exampleTeam.UUID)
			return err
		})
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("create a request to join a team", func(t *testing.T) {

		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "test4@example.com",
		}

		mockResponse := callAPI(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
			requestData, &exampledata.ExampleFingerprint4)

		t.Run("status code 201 created", func(t *testing.T) {
			assertStatusCode(t, http.StatusCreated, mockResponse.Code)
		})
	})

	testEndpointRejectsBadJSON(t,
		"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
		&exampledata.ExampleFingerprint4)

	testEndpointRejectsUnauthenticated(t,
		"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
		v1structs.RequestToJoinTeamRequest{})

	t.Run("for non existent team", func(t *testing.T) {
		mockResponse := callAPI(t,
			// this team UUID doesn't exist
			"POST", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810/requests-to-join", nil, nil)

		t.Run("status code 400 bad request", func(t *testing.T) {
			assertStatusCode(t, http.StatusBadRequest, mockResponse.Code)
		})
	})

	t.Run("missing teamEmail", func(t *testing.T) {
		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "",
		}

		mockResponse := callAPI(t,
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
		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "conflicting-example@example.com",
		}

		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "conflicting-example@example.com", exampledata.ExampleFingerprint4, nil,
			))

		deleteRequests()

		firstResponse := callAPI(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
			requestData, &exampledata.ExampleFingerprint4)

		assertStatusCode(t, http.StatusCreated, firstResponse.Code) // first request succeeds

		// insert exmaple key 2 as a conflicting key but with the same email

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "conflicting-example@example.com", exampledata.ExampleFingerprint2, nil,
			))

		secondResponse := callAPI(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
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

	t.Run("existing {team, email, fingerprint} request should succeed", func(t *testing.T) {
		requestData := v1structs.RequestToJoinTeamRequest{
			TeamEmail: "test4@example.com",
		}

		deleteRequests()

		firstResponse := callAPI(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
			requestData, &exampledata.ExampleFingerprint4)

		if firstResponse.Code != http.StatusCreated {
			t.Fatalf("failed to create team join request, got http %d", firstResponse.Code)
		}

		secondResponse := callAPI(t,
			"POST", fmt.Sprintf("/v1/team/%s/requests-to-join", exampleTeam.UUID),
			// same fingerprint as previous request: should succeed
			requestData, &exampledata.ExampleFingerprint4)

		t.Run("returns http 200 OK", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, secondResponse.Code)
		})
	})
}

func TestDeleteRequestToJoinTeamHandler(t *testing.T) {
	teamUUID, err := uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")
	assert.NoError(t, err)

	goodRoster := `
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
is_admin = true
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

	setup := func() uuid.UUID {
		assert.NoError(t,
			datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))

		assert.NoError(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4, nil,
			),
		)

		assert.NoError(t,
			datastore.UpsertTeam(nil, goodTeam),
		)

		requestUUID, err := datastore.CreateRequestToJoinTeam(
			nil,
			teamUUID,
			"request@example.com",
			fingerprint.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB"),
			now,
		)
		assert.NoError(t, err)
		return *requestUUID
	}

	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)

		_, err = datastore.DeleteTeam(nil, teamUUID)
		assert.NoError(t, err)
	}

	requestToJoinUUID := setup()
	defer teardown()

	t.Run("deletes a request", func(t *testing.T) {
		response := callAPI(
			t,
			"DELETE",
			fmt.Sprintf("/v1/team/%s/requests-to-join/%s", teamUUID, requestToJoinUUID),
			nil,
			nil,
		)

		t.Run("status code 202", func(t *testing.T) {
			assertStatusCode(t, http.StatusAccepted, response.Code)
		})

		t.Run("removes request from datastore", func(t *testing.T) {
			requestsToJoinTeam, err := datastore.GetRequestsToJoinTeam(nil, teamUUID)
			assert.NoError(t, err)
			assert.Equal(t, 0, len(requestsToJoinTeam))
		})
	})

	t.Run("returns bad request for invalid request UUID", func(t *testing.T) {
		response := callAPI(
			t,
			"DELETE",
			fmt.Sprintf("/v1/team/%s/requests-to-join/invalid-uuid", teamUUID),
			nil,
			nil,
		)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
	})

	t.Run("returns not found for missing request UUID", func(t *testing.T) {
		response := callAPI(
			t,
			"DELETE",
			fmt.Sprintf("/v1/team/%s/requests-to-join/%s", teamUUID, uuid.Must(uuid.NewV4())),
			nil,
			nil,
		)
		assertStatusCode(t, http.StatusNotFound, response.Code)
	})
}

func TestGetTeamRoster(t *testing.T) {
	now := time.Date(2019, 2, 28, 16, 35, 45, 0, time.UTC)
	roster := `
            name = "Example"
			uuid = "18d12a10-4678-11e9-ba93-2385e4a50ded"

			[[ person ]]
			email = "test4@example.com"
			fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
			is_admin = true`

	team := datastore.Team{
		UUID:            uuid.Must(uuid.FromString("18d12a10-4678-11e9-ba93-2385e4a50ded")),
		Roster:          roster,
		RosterSignature: "fake signature",
		CreatedAt:       now,
	}

	setup := func() {
		assert.NoError(t, datastore.UpsertTeam(nil, team))

		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		assert.NoError(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
	}

	teardown := func() {
		_, err := datastore.DeleteTeam(nil, team.UUID)
		assert.NoError(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.NoError(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint2)
		assert.NoError(t, err)
	}

	setup()
	defer teardown()

	t.Run("get roster for a valid team member", func(t *testing.T) {
		responseData := v1structs.GetTeamRosterResponse{} // placeholder

		response := callAPI(t,
			"GET", fmt.Sprintf("/v1/team/%s/roster", team.UUID),
			nil, &exampledata.ExampleFingerprint4,
		)

		t.Run("returns HTTP 200 OK", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("response has json content type", func(t *testing.T) {
			assert.Equal(t, "application/json", response.Header().Get("content-type"))
		})

		t.Run("body is JSON which decodes as GetTeamRosterResponse", func(t *testing.T) {
			err := json.NewDecoder(response.Body).Decode(&responseData)
			assert.NoError(t, err)
		})

		t.Run("encryptedJSON decrypts as valid, correct JSON", func(t *testing.T) {
			unlockedKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
				exampledata.ExamplePrivateKey4, "test4",
			)
			assert.NoError(t, err)

			if responseData.EncryptedJSON == "" {
				t.Fatal("empty encryptedJSON response")
			}

			ciphertext, err := decryptMessage(responseData.EncryptedJSON, unlockedKey)
			assert.NoError(t, err)

			// decrypted JSON decodes as TeamRosterAndSignature?
			teamRosterAndSignature := v1structs.TeamRosterAndSignature{}
			err = json.NewDecoder(ciphertext).Decode(&teamRosterAndSignature)
			assert.NoError(t, err)

			// decrypted roster matches?
			assert.Equal(t, team.Roster, teamRosterAndSignature.TeamRoster)

			// decrypted signature matches?
			assert.Equal(t, team.RosterSignature, teamRosterAndSignature.ArmoredDetachedSignature)
		})

		t.Run("responseData.teamRoster", func(t *testing.T) {
			assert.Equal(t, team.Roster, responseData.TeamRoster)
		})

		t.Run("responseData.armoredDetachedSignature", func(t *testing.T) {
			assert.Equal(t, team.RosterSignature, responseData.ArmoredDetachedSignature)
		})

	})

	testEndpointRejectsUnauthenticated(t, "GET", fmt.Sprintf("/v1/team/%s/roster", team.UUID), nil)

	t.Run("for non existent team", func(t *testing.T) {
		response := callAPI(t,
			"GET", "/v1/team/8d79a1a6-3b67-11e9-b2dc-9f62d9775810/roster", // UUID does not exist
			nil, &exampledata.ExampleFingerprint4,
		)

		t.Run("status code 404", func(t *testing.T) {
			assertStatusCode(t, http.StatusNotFound, response.Code)
		})
	})

	t.Run("request key is not in the roster returns 403 forbidden", func(t *testing.T) {
		response := callAPI(t,
			"GET", fmt.Sprintf("/v1/team/%s/roster", team.UUID),
			nil, &exampledata.ExampleFingerprint2,
		)

		assertStatusCode(t, http.StatusForbidden, response.Code)
		assertHasJSONErrorDetail(t, response.Body, "requesting key is not in the team")
	})

}
