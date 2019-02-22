package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/clearsign"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if testDatabaseURL, got := os.LookupEnv("TEST_DATABASE_URL"); got {
		datastore.Initialize(testDatabaseURL)
	} else {
		panic("TEST_DATABASE_URL not set")
	}

	err := datastore.Migrate()
	if err != nil {
		panic(fmt.Errorf("failed to migrate test database: %v", err))
	}

	code := m.Run()

	err = datastore.DropAllTheTables()
	if err != nil {
		panic(fmt.Errorf("failed to empty test database: %v", err))
	}

	os.Exit(code)
}

func TestPingEndpoint(t *testing.T) {
	t.Run("test ping endpoint", func(t *testing.T) {
		mockResponse := callAPI(t, "GET", "/v1/ping/foo")

		assertStatusCode(t, http.StatusOK, mockResponse.Code)

		// Check the response body is what we expect.
		expected := `foo`
		got := mockResponse.Body.String()

		if got != expected {
			t.Errorf("unexpected body, expected %v, got %v", expected, got)
		}
	})
}

func TestGetPublicKeyByEmailHandler(t *testing.T) {
	assert.ErrorIsNil(t,
		datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4),
	)
	assert.ErrorIsNil(t,
		datastore.LinkEmailToFingerprint(nil, "test4@example.com", exampledata.ExampleFingerprint4),
	)
	assert.ErrorIsNil(t,
		datastore.LinkEmailToFingerprint(nil, "test4+foo@example.com", exampledata.ExampleFingerprint4),
	)

	t.Run("JSON endpoint", func(t *testing.T) {
		t.Run("with no match on email", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/missing@example.com/key")

			assertStatusCode(t, http.StatusNotFound, response.Code)
			assertHasJSONErrorDetail(t, response.Body,
				"couldn't find a public key for email address 'missing@example.com'")
		})

		t.Run("with match on email", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4@example.com/key")
			assertStatusCode(t, http.StatusOK, response.Code)

			responseData := v1structs.GetPublicKeyResponse{}
			assertBodyDecodesInto(t, response.Body, &responseData)
			assert.Equal(t, responseData.ArmoredPublicKey, exampledata.ExamplePublicKey4)
		})

		t.Run("with + in email, request not urlencoded", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4+foo@example.com/key")
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("with + in email, request urlencoded", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4%2Bfoo%40example.com/key")
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("with uppercase query for lowercase email", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/TEST4@example.com/key")
			assertStatusCode(t, http.StatusOK, response.Code)
		})
	})

	t.Run("ascii-armored endpoint", func(t *testing.T) {
		t.Run("with no match on email", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/missing@example.com/key.asc")

			assertStatusCode(t, http.StatusNotFound, response.Code)
			assertHasJSONErrorDetail(t, response.Body,
				"couldn't find a public key for email address 'missing@example.com'")
		})

		t.Run("with match on email", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4@example.com/key.asc")
			assertStatusCode(t, http.StatusOK, response.Code)
			assertBodyEqualTo(t, response.Body, exampledata.ExamplePublicKey4)
		})

		t.Run("with + in email, request not urlencoded", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4+foo@example.com/key.asc")
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("with + in email, request urlencoded", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/email/test4%2Bfoo%40example.com/key.asc")
			assertStatusCode(t, http.StatusOK, response.Code)
		})
	})
}

func TestGetPublicKeyByFingerprintHandler(t *testing.T) {
	assert.ErrorIsNil(t,
		datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4),
	)

	t.Run("JSON endpoint", func(t *testing.T) {
		t.Run("with no matching fingerprint", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/key/"+exampledata.ExampleFingerprint3.Hex())

			assertStatusCode(t, http.StatusNotFound, response.Code)
			assertHasJSONErrorDetail(t, response.Body,
				"fingerprint looked valid, but no public key found for "+
					"'7C18 DE4D E478 1356 8B24  3AC8 719B D63E F03B DC20'")
		})

		t.Run("with a matching fingerprint", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/key/"+exampledata.ExampleFingerprint4.Hex())
			assertStatusCode(t, http.StatusOK, response.Code)

			responseData := v1structs.GetPublicKeyResponse{}
			assertBodyDecodesInto(t, response.Body, &responseData)
			assert.Equal(t, responseData.ArmoredPublicKey, exampledata.ExamplePublicKey4)
		})
	})

	t.Run("ascii-armored endpoint", func(t *testing.T) {
		t.Run("with no matching fingerprint", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/key/"+exampledata.ExampleFingerprint3.Hex()+".asc")

			assertStatusCode(t, http.StatusNotFound, response.Code)
			assertHasJSONErrorDetail(t, response.Body,
				"fingerprint looked valid, but no public key found for "+
					"'7C18 DE4D E478 1356 8B24  3AC8 719B D63E F03B DC20'")
		})

		t.Run("with a matching fingerprint", func(t *testing.T) {
			response := callAPI(t, "GET", "/v1/key/"+exampledata.ExampleFingerprint4.Hex()+".asc")
			assertStatusCode(t, http.StatusOK, response.Code)

			assertBodyEqualTo(t, response.Body, exampledata.ExamplePublicKey4)
		})
	})

}

func TestUpsertPublicKeyHandler(t *testing.T) {
	armoredPublicKey := exampledata.ExamplePublicKey4
	validSha256 := fmt.Sprintf("%X", sha256.Sum256([]byte(exampledata.ExamplePublicKey4)))
	publicKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	assert.ErrorIsNil(t, err)

	unlockedKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	assert.ErrorIsNil(t, err)

	uuid1 := uuid.Must(uuid.NewV4())
	now := time.Date(2018, 6, 15, 16, 30, 0, 0, time.UTC)

	setup := func() {

	}

	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)
	}

	makeSignedData := func(t *testing.T, timestamp time.Time, uuidString string, sha256 string) string {
		t.Helper()
		upsertPublicKeyJSON := new(bytes.Buffer)

		err := json.NewEncoder(upsertPublicKeyJSON).Encode(
			v1structs.UpsertPublicKeySignedData{
				Timestamp:       timestamp,
				SingleUseUUID:   uuidString,
				PublicKeySHA256: sha256,
			})
		assert.ErrorIsNil(t, err)

		signedData, err := signText(upsertPublicKeyJSON.Bytes(), unlockedKey)
		assert.ErrorIsNil(t, err)
		return signedData
	}

	setup()

	// TODO: content header tests etc

	t.Run("bad (truncated) signature", func(t *testing.T) {
		goodSig := makeSignedData(t, now, uuid1.String(), validSha256)

		truncatedSignature := goodSig[0 : len(goodSig)/2]

		_, err := validateSignedData(truncatedSignature, armoredPublicKey, publicKey, now)
		assert.Equal(t, "failed to verify: error finding clearsigned data", err.Error())
	})

	t.Run("mismatching SHA256", func(t *testing.T) {
		armoredSignedData := makeSignedData(t, now, uuid1.String(), "0a0a")
		_, err := validateSignedData(armoredSignedData, armoredPublicKey, publicKey, now)
		assert.Equal(t, "mismatching public key SHA256", err.Error())
	})

	t.Run("timestamp too far in the future", func(t *testing.T) {
		thirtyHoursFromNow := now.Add(time.Hour * time.Duration(30))
		armoredSignedData := makeSignedData(t, thirtyHoursFromNow, uuid1.String(), validSha256)

		_, err := validateSignedData(armoredSignedData, armoredPublicKey, publicKey, now)
		assert.Equal(t, "timestamp is not within 24 hours of server time", err.Error())
	})

	t.Run("timestamp too far in the past", func(t *testing.T) {
		thirtyHoursInPast := now.Add(time.Hour * time.Duration(-30))
		armoredSignedData := makeSignedData(t, thirtyHoursInPast, uuid1.String(), validSha256)

		_, err := validateSignedData(armoredSignedData, armoredPublicKey, publicKey, now)
		assert.Equal(t, "timestamp is not within 24 hours of server time", err.Error())
	})

	t.Run("single use UUID not a valid UUID", func(t *testing.T) {
		armoredSignedData := makeSignedData(t, now, "foo", validSha256)

		_, err := validateSignedData(armoredSignedData, armoredPublicKey, publicKey, now)
		assert.Equal(t, "bad SingleUseUUID: uuid: incorrect UUID length: foo", err.Error())
	})

	t.Run("single use UUID already used", func(t *testing.T) {
		repeatedUUID := uuid.Must(uuid.NewV4())

		datastore.StoreSingleUseNumber(nil, repeatedUUID, now)

		armoredSignedData := makeSignedData(t, now, repeatedUUID.String(), validSha256)

		_, err := validateSignedData(armoredSignedData, armoredPublicKey, publicKey, now)
		assert.Equal(t, "bad SingleUseUUID: single use UUID already used", err.Error())
	})

	t.Run("valid signed data, brand new key", func(t *testing.T) {

		requestData := v1structs.UpsertPublicKeyRequest{
			ArmoredPublicKey: exampledata.ExamplePublicKey4,
			ArmoredSignedJSON: makeSignedData(
				t,
				time.Now(),
				uuid.Must(uuid.NewV4()).String(),
				validSha256),
		}

		response := callAPIWithJSON(t, "POST", "/v1/keys", requestData)
		fmt.Print(response.Body)
		assertStatusCode(t, http.StatusOK, response.Code)

		responseData := v1structs.UpsertPublicKeyResponse{}
		err = json.NewDecoder(response.Body).Decode(&responseData)
		assert.ErrorIsNil(t, err)

		newPasswordReader, err := decryptMessage(responseData.ArmoredEncryptedBasicAuthPassword, unlockedKey)
		assert.ErrorIsNil(t, err)

		buf := new(bytes.Buffer)
		buf.ReadFrom(newPasswordReader)

		_, err = uuid.FromString(buf.String())
		assert.ErrorIsNil(t, err)
	})

	teardown()
}

func TestSendSecretHandler(t *testing.T) {

	key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey4)
	assert.ErrorIsNil(t, err)

	otherKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	assert.ErrorIsNil(t, err)
	unknownFingerprint := fingerprint.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB")

	validEncryptedArmoredSecret, err := encryptStringToArmor("test foo", key)

	setup := func() {
		// put `key` and `otherKey` in the datastore, but not `unknownFingerprint`
		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey3))
	}
	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint3)
		assert.ErrorIsNil(t, err)
	}

	setup()

	t.Run("good recipient and ascii armor", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusCreated, response.Code)
	})

	t.Run("request missing content-type header", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"expecting header Content-Type: application/json")
	})

	t.Run("request content-type header isn't application/json", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "multipart/form-data")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"expecting header Content-Type: application/json")
	})

	t.Run("empty request body", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body, "empty request body")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", strings.NewReader("invalid json"))
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid JSON: invalid character 'i' looking for beginning of value")
	})

	t.Run("empty recipientFingerprint", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   "",
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid `recipientFingerprint`: missing prefix `OPENPGP4FPR:`")
	})

	t.Run("malformed recipientFingerprint", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   "A999B7498D1A8DC473E53C92309F635DAD1B5517", // no prefix
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid `recipientFingerprint`: missing prefix `OPENPGP4FPR:`")
	})

	t.Run("recipientFingerprint not in the database", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   unknownFingerprint.Uri(),
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body, "no key found for fingerprint")
	})

	t.Run("empty armoredEncryptedSecret", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: "",
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid `armoredEncryptedSecret`: empty string")
	})

	t.Run("armoredEncryptedSecret invalid ascii armor", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: "bad ASCII armor",
		}

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid `armoredEncryptedSecret`: error decoding ASCII armor: EOF")
	})

	t.Run("armoredEncryptedSecret contains invalid packets", func(t *testing.T) {
		// secret should have 2 packets, like this:
		// New: Public-Key Encrypted Session Key Packet(tag 1)(268 bytes)
		// New: Symmetrically Encrypted and MDC Packet(tag 18)(1 bytes) partial start

		// TODO
	})

	t.Run("armoredEncryptedSecret encrypted to wrong recipient", func(t *testing.T) {
		t.Skip()
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   otherKey.Fingerprint().Uri(),
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		// TODO: would be nice one day to test this.
		// assertStatusCode(t, http.StatusBadRequest, response.Code)
		// assertHasJsonErrorDetail(t, response.Body,
		// 	"secret is encryped to a different key")
	})

	t.Run("armoredEncryptedSecret longer then 20K", func(t *testing.T) {
		const msgLength int = 21 * 1024
		const letter rune = 'a'
		runes := make([]rune, msgLength)

		for i := range runes {
			runes[i] = letter
		}

		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint: fmt.Sprintf("OPENPGP4FPR:%s", key.Fingerprint().Hex()),
		}
		requestData.ArmoredEncryptedSecret, err = encryptStringToArmor(string(runes), key)
		assert.ErrorIsNil(t, err)

		response := callAPIWithJSON(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"invalid `armoredEncryptedSecret`: secrets currently have a "+
				"max size of 10240 bytes")
	})

	teardown()

}

func TestListSecretsHandler(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey4)
	assert.ErrorIsNil(t, err)

	// otherKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	assert.ErrorIsNil(t, err)
	unknownFingerprint := fingerprint.MustParse("AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB")

	validEncryptedArmoredSecret, err := encryptStringToArmor("test foo", key)

	var secretUUID *uuid.UUID

	setup := func() {
		now := time.Date(2018, 6, 5, 16, 30, 5, 0, time.UTC)
		// put `key` and `otherKey` in the datastore, but not `unknownFingerprint`
		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey3))
		secretUUID, err = datastore.CreateSecret(
			exampledata.ExampleFingerprint4, validEncryptedArmoredSecret, now)
		assert.ErrorIsNil(t, err)
	}
	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)

		_, err = datastore.DeletePublicKey(exampledata.ExampleFingerprint3)
		assert.ErrorIsNil(t, err)

		_, err = datastore.DeleteSecret(*secretUUID, exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)
	}

	setup()

	t.Run("without authorization header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)
		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusUnauthorized, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	})

	t.Run("malformed authorization header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set("Authorization", "invalid")
		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusUnauthorized, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	})

	t.Run("no matching public key", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set(
			"Authorization",
			fmt.Sprintf("tmpfingerprint: %s", unknownFingerprint.Uri()),
		)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusUnauthorized, response.Code)
		assertHasJSONErrorDetail(t, response.Body, "invalid authorization")
	})

	t.Run("valid request with no secrets", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set(
			"Authorization",
			fmt.Sprintf("tmpfingerprint: %s", exampledata.ExampleFingerprint3.Uri()),
		)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusOK, response.Code)

		responseData := v1structs.ListSecretsResponse{}
		err = json.NewDecoder(response.Body).Decode(&responseData)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, 0, len(responseData.Secrets))
	})

	t.Run("valid request with 1 secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set(
			"Authorization",
			fmt.Sprintf("tmpfingerprint: %s", exampledata.ExampleFingerprint4.Uri()),
		)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)
		responseData := v1structs.ListSecretsResponse{}

		t.Run("returns http 200", func(t *testing.T) {
			assertStatusCode(t, http.StatusOK, response.Code)
		})

		t.Run("returns expected JSON", func(t *testing.T) {
			if response.Body == nil {
				t.Fatal("response has nil Body")
			}
			err := json.NewDecoder(response.Body).Decode(&responseData)
			assert.ErrorIsNil(t, err)
		})

		t.Run("JSON has one secret", func(t *testing.T) {
			assert.Equal(t, 1, len(responseData.Secrets))
		})

		t.Run("encryptedContent is unaltered", func(t *testing.T) {
			assert.Equal(t, validEncryptedArmoredSecret, responseData.Secrets[0].EncryptedContent)
		})

		t.Run("encryptedMetadata can be decrypted", func(t *testing.T) {
			privateKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
				exampledata.ExamplePrivateKey4, "test4")
			assert.ErrorIsNil(t, err)
			msg, err := decryptMessage(
				responseData.Secrets[0].EncryptedMetadata, privateKey)
			assert.ErrorIsNil(t, err)

			t.Run("metadata has correct secret UUID", func(t *testing.T) {
				metadata := v1structs.SecretMetadata{}
				err := json.NewDecoder(msg).Decode(&metadata)
				assert.ErrorIsNil(t, err)

				gotUUID, err := uuid.FromString(metadata.SecretUUID)
				if err != nil {
					t.Fatalf("failed to parse secretUUID '%s' as UUID", metadata.SecretUUID)
				} else if gotUUID.Version() != uuid.V4 {
					t.Fatalf("expected UUID version 4, got %v", secretUUID.Version())
				} else if *secretUUID != gotUUID {
					t.Fatalf("decrypted secret UUID didn't match, expected %v, got %v",
						secretUUID, metadata.SecretUUID)
				}
			})
		})

	})

	teardown()

}

func TestDeleteSecretHandler(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey4)
	assert.ErrorIsNil(t, err)

	// otherKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	assert.ErrorIsNil(t, err)

	validEncryptedArmoredSecret, err := encryptStringToArmor("test foo", key)

	var secretUUID *uuid.UUID

	setup := func() {
		now := time.Date(2018, 6, 5, 16, 30, 5, 0, time.UTC)
		assert.ErrorIsNil(t, datastore.UpsertPublicKey(nil, exampledata.ExamplePublicKey4))
		secretUUID, err = datastore.CreateSecret(
			exampledata.ExampleFingerprint4, validEncryptedArmoredSecret, now)
		assert.ErrorIsNil(t, err)
	}
	teardown := func() {
		_, err := datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)
	}

	setup()

	t.Run("invalid UUID in URL", func(t *testing.T) {
		req, err := http.NewRequest("DELETE", "/v1/secrets/invalid-uuid", nil)
		assert.ErrorIsNil(t, err)
		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusNotFound, response.Code)
	})

	t.Run("without authorization header", func(t *testing.T) {
		req, err := http.NewRequest("DELETE", "/v1/secrets/"+secretUUID.String(), nil)
		assert.ErrorIsNil(t, err)
		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusUnauthorized, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	})

	t.Run("malformed authorization header", func(t *testing.T) {
		req, err := http.NewRequest("DELETE", "/v1/secrets/"+secretUUID.String(), nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set("Authorization", "invalid")
		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusUnauthorized, response.Code)
		assertHasJSONErrorDetail(t, response.Body,
			"missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	})

	t.Run("delete secret good request", func(t *testing.T) {
		req, err := http.NewRequest("DELETE", "/v1/secrets/"+secretUUID.String(), nil)
		assert.ErrorIsNil(t, err)
		req.Header.Set(
			"Authorization",
			fmt.Sprintf("tmpfingerprint: %s", exampledata.ExampleFingerprint4.Uri()),
		)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusAccepted, response.Code)

		secrets, err := datastore.GetSecrets(exampledata.ExampleFingerprint4)
		assert.ErrorIsNil(t, err)
		if len(secrets) != 0 {
			t.Fatalf("expected 0 secrets after delete, got %d: %v", len(secrets), secrets)
		}
	})

	teardown()
}

func callAPI(t *testing.T, method string, path string) *httptest.ResponseRecorder {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	t.Helper()

	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder() // create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	subrouter.ServeHTTP(recorder, req)

	return recorder
}

func callAPIWithJSON(t *testing.T, method string, path string, requestData interface{}) *httptest.ResponseRecorder {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	t.Helper()

	if requestData == nil {
		t.Fatalf("you must pass in requestData")
	}

	body := new(bytes.Buffer)

	if requestData != nil { // we're sending JSON data
		encoder := json.NewEncoder(body)
		err := encoder.Encode(requestData)
		if err != nil {
			t.Fatalf("failed to encode requestData as JSON: %v", err)
		}
	}

	req, err := http.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder() // create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	subrouter.ServeHTTP(recorder, req)

	return recorder
}

func assertStatusCode(t *testing.T, expected int, got int) {
	t.Helper()
	if expected != got {
		t.Fatalf("expected HTTP %d, got HTTP %d", expected, got)
	}
}

func assertHasJSONErrorDetail(t *testing.T, body io.Reader, expectedDetail string) {
	t.Helper()
	errorResponse := v1structs.ErrorResponse{}
	if err := json.NewDecoder(body).Decode(&errorResponse); err != nil {
		t.Fatalf("failed to decode body as JSON: %v", err)
	} else if errorResponse.Detail != expectedDetail {
		t.Fatalf("expected error detail '%s', got '%s'", expectedDetail, errorResponse.Detail)
	}
}

func assertBodyDecodesInto(t *testing.T, body io.Reader, responseStruct interface{}) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(&responseStruct); err != nil {
		t.Fatalf("failed to decode body as JSON: %v", err)
	}
}

func assertBodyEqualTo(t *testing.T, bodyReader io.Reader, expectedBody string) {
	body, err := ioutil.ReadAll(bodyReader)
	assert.ErrorIsNil(t, err)

	assert.Equal(t, string(body), exampledata.ExamplePublicKey4)
}

func decryptMessage(armoredEncryptedSecret string, key *pgpkey.PgpKey) (io.Reader, error) {
	block, err := armor.Decode(strings.NewReader(armoredEncryptedSecret))
	if err != nil {
		return nil, fmt.Errorf("error decoding armor: %s", err)
	}

	var keyRing openpgp.EntityList = []*openpgp.Entity{&key.Entity}

	messageDetails, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error rereading message: %s", err)
	}

	decryptedBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(decryptedBuf, messageDetails.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("error rereading message: %s", err)
	}

	if messageDetails.SignatureError != nil {
		return nil, fmt.Errorf("signature error: %v", err)
	}
	return decryptedBuf, nil
}

func signText(bytesToSign []byte, key *pgpkey.PgpKey) (armoredSigned string, err error) {
	armorOutBuffer := bytes.NewBuffer(nil)
	privKey := key.Entity.PrivateKey

	armorWriteCloser, err := clearsign.Encode(armorOutBuffer, privKey, nil)
	if err != nil {
		return "", err
	}

	_, err = armorWriteCloser.Write(bytesToSign)
	if err != nil {
		return "", err
	}

	armorWriteCloser.Close()
	return armorOutBuffer.String(), nil
}
