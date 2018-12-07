package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if testDatabaseUrl, got := os.LookupEnv("TEST_DATABASE_URL"); got {
		datastore.Initialize(testDatabaseUrl)
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
		mockResponse := callApi(t, "GET", "/v1/ping/foo")

		assertStatusCode(t, http.StatusOK, mockResponse.Code)

		// Check the response body is what we expect.
		expected := `foo`
		got := mockResponse.Body.String()

		if got != expected {
			t.Errorf("unexpected body, expected %v, got %v", expected, got)
		}
	})
}

func TestGetPublicKeyHandler(t *testing.T) {
	assert.ErrorIsNil(t,
		datastore.UpsertPublicKey(exampledata.ExamplePublicKey4),
	)
	assert.ErrorIsNil(t,
		datastore.LinkEmailToFingerprint("test4@example.com", exampledata.ExampleFingerprint4),
	)
	assert.ErrorIsNil(t,
		datastore.LinkEmailToFingerprint("test4+foo@example.com", exampledata.ExampleFingerprint4),
	)

	t.Run("with no match on email", func(t *testing.T) {
		response := callApi(t, "GET", "/v1/email/missing@example.com/key")

		assertStatusCode(t, http.StatusNotFound, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"couldn't find a public key for email address 'missing@example.com'")
	})

	t.Run("with match on email", func(t *testing.T) {
		response := callApi(t, "GET", "/v1/email/test4@example.com/key")
		assertStatusCode(t, http.StatusOK, response.Code)

		responseData := v1structs.GetPublicKeyResponse{}
		assertBodyDecodesInto(t, response.Body, &responseData)
		assert.Equal(t, responseData.ArmoredPublicKey, exampledata.ExamplePublicKey4)
	})

	t.Run("with + in email, request not urlencoded", func(t *testing.T) {
		response := callApi(t, "GET", "/v1/email/test4+foo@example.com/key")
		assertStatusCode(t, http.StatusOK, response.Code)
	})

	t.Run("with + in email, request urlencoded", func(t *testing.T) {
		response := callApi(t, "GET", "/v1/email/test4%2Bfoo%40example.com/key")
		assertStatusCode(t, http.StatusOK, response.Code)
	})
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
		datastore.UpsertPublicKey(exampledata.ExamplePublicKey4)
		datastore.UpsertPublicKey(exampledata.ExamplePublicKey3)
	}
	teardown := func() {
		datastore.DeletePublicKey(exampledata.ExampleFingerprint4)
		datastore.DeletePublicKey(exampledata.ExampleFingerprint3)
	}

	setup()

	t.Run("good recipient and ascii armor", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusCreated, response.Code)
	})

	t.Run("request missing content-type header", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"expecting header Content-Type: application/json")
	})

	t.Run("request content-type header isn't application/json", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "multipart/form-data")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"expecting header Content-Type: application/json")
	})

	t.Run("empty request body", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", nil)
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body, "empty request body")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/v1/secrets", strings.NewReader("invalid json"))
		assert.ErrorIsNil(t, err)

		req.Header.Set("Content-Type", "application/json")

		response := httptest.NewRecorder()
		subrouter.ServeHTTP(response, req)

		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"invalid JSON: invalid character 'i' looking for beginning of value")
	})

	t.Run("empty recipientFingerprint", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   "",
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"invalid `recipientFingerprint`: missing prefix OPENPGP4FPR:")
	})

	t.Run("malformed recipientFingerprint", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   "A999B7498D1A8DC473E53C92309F635DAD1B5517", // no prefix
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"invalid `recipientFingerprint`: missing prefix OPENPGP4FPR:")
	})

	t.Run("recipientFingerprint not in the database", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   unknownFingerprint.Uri(),
			ArmoredEncryptedSecret: validEncryptedArmoredSecret,
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body, "no key found for fingerprint")
	})

	t.Run("empty armoredEncryptedSecret", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: "",
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"invalid `armoredEncryptedSecret`: empty string")
	})

	t.Run("armoredEncryptedSecret invalid ascii armor", func(t *testing.T) {
		requestData := v1structs.SendSecretRequest{
			RecipientFingerprint:   key.Fingerprint().Uri(),
			ArmoredEncryptedSecret: "bad ASCII armor",
		}

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
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

		callApiWithJson(t, "POST", "/v1/secrets", requestData)
		// TODO: would be nice one day to test this.
		// assertStatusCode(t, http.StatusBadRequest, response.Code)
		// assertHasJsonErrorDetail(t, response.Body,
		// 	"secret is encryped to a different key")
	})

	t.Run("armoredEncryptedSecret longer then 10K", func(t *testing.T) {
		const msgLength int = 11 * 1024
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

		response := callApiWithJson(t, "POST", "/v1/secrets", requestData)
		assertStatusCode(t, http.StatusBadRequest, response.Code)
		assertHasJsonErrorDetail(t, response.Body,
			"invalid `armoredEncryptedSecret`: secrets currently have a max size of 10K")
	})

	teardown()

}

func callApi(t *testing.T, method string, path string) *httptest.ResponseRecorder {
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

func callApiWithJson(t *testing.T, method string, path string, requestData interface{}) *httptest.ResponseRecorder {
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

func assertHasJsonErrorDetail(t *testing.T, body io.Reader, expectedDetail string) {
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
