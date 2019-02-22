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

	assert.ErrorIsNil(t, err)

	duplicateUUID, err := uuid.NewV4() // this is used to test the duplicated case
	assert.ErrorIsNil(t, err)

	goodUUID, err := uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")
	assert.ErrorIsNil(t, err)

	goodRoster := `
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"

[[person]]
email = "b@example.com"
fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
`

	goodSignature, err := makeArmoredDetachedSignature([]byte(goodRoster), unlockedKey)
	assert.ErrorIsNil(t, err)

	setup := func() {
		assert.ErrorIsNil(t,
			datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))

		assert.ErrorIsNil(t,
			datastore.LinkEmailToFingerprint(
				nil, "test4@example.com", exampledata.ExampleFingerprint4,
			),
		)

	}

	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)

		_, err = datastore.DeleteTeam(nil, goodUUID)
		assert.ErrorIsNil(t, err)

		_, err = datastore.DeleteTeam(nil, duplicateUUID)
		assert.ErrorIsNil(t, err)
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
			assert.ErrorIsNil(t, err)

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

	testEndpointRejectsBadJSON(t, "POST", "/v1/teams")

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

		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey2))
		assert.ErrorIsNil(t,
			datastore.LinkEmailToFingerprint(nil, "test2@example.com", mismatchedFingerprint))

		assert.ErrorIsNil(t, err)

		requestData := v1structs.UpsertTeamRequest{
			TeamRoster:               goodRoster,
			ArmoredDetachedSignature: goodSignature,
		}

		response := callAPIWithJSON(t, "POST", "/v1/teams", requestData, &mismatchedFingerprint)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"signature verification failed")

		_, err := datastore.DeletePublicKey(mismatchedFingerprint)
		assert.ErrorIsNil(t, err)
	})

	t.Run("dont have public key that signed the roster", func(t *testing.T) {
		keyNotInAPI, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
			exampledata.ExamplePrivateKey3, "test3")
		fingerprintNotInAPI := keyNotInAPI.Fingerprint()
		assert.ErrorIsNil(t, err)

		signature, err := makeArmoredDetachedSignature([]byte(goodRoster), keyNotInAPI)
		assert.ErrorIsNil(t, err)

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

[[person]]
email = "test4@example.com"
fingerprint = "BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB"
`

		fingerprintTwice := `
uuid = "9ca4a81e-3532-11e9-9145-a3dd42867f07"

[[person]]
email = "test4@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"

[[person]]
email = "b@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
`

		signingKeyNotInRoster := `
uuid = "344672d2-35e8-11e9-ade3-93c56fb48f08"

[[person]]
email = "test4@example.com"
fingerprint = "AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA"
`

		unverifiedEmailInRoster := `
uuid = "113ab4ba-35e8-11e9-8aa6-f721c118df12"

[[person]]
email = "unverified-email@example.com"
fingerprint = "BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 33D7 F9D6"
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
				testName:            "signing key's fingerprint isn't listed in roster",
				roster:              signingKeyNotInRoster,
				expectedErrorDetail: "signing key's fingerprint isn't listed in roster",
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
				assert.ErrorIsNil(t, err)

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

[[person]]
email = "b@example.com"
fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
`

		signature, err := makeArmoredDetachedSignature([]byte(duplicatedRoster), unlockedKey)
		assert.ErrorIsNil(t, err)

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
