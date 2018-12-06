package server

import (
	"encoding/json"
	"fmt"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func assertStatusCode(t *testing.T, expected int, got int) {
	if expected != got {
		t.Fatalf("expected HTTP %d, got HTTP %d", expected, got)
	}
}

func assertHasJsonErrorDetail(t *testing.T, body io.Reader, expectedDetail string) {
	errorResponse := v1structs.ErrorResponse{}
	if err := json.NewDecoder(body).Decode(&errorResponse); err != nil {
		t.Fatalf("failed to decode body as JSON: %v", err)
	} else if errorResponse.Detail != expectedDetail {
		t.Fatalf("expected error detail '%s', got '%s'", expectedDetail, errorResponse.Detail)
	}
}

func assertBodyDecodesInto(t *testing.T, body io.Reader, responseStruct interface{}) {
	if err := json.NewDecoder(body).Decode(&responseStruct); err != nil {
		t.Fatalf("failed to decode body as JSON: %v", err)
	}
}
