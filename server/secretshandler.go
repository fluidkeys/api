package server

import (
	"encoding/json"
	"fmt"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"net/http"
	"strings"
	"time"
)

func sendSecretHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	requestData := v1structs.SendSecretRequest{}
	err := decoder.Decode(&requestData)
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	fpr, err := parseFingerprint(requestData.RecipientFingerprint)
	if err != nil {
		writeJsonError(
			w,
			fmt.Errorf("invalid `recipientFingerprint`: %v", err),
			http.StatusBadRequest,
		)
		return
	}

	err = validateSecret(requestData.ArmoredEncryptedSecret)
	if err != nil {
		writeJsonError(
			w,
			fmt.Errorf("invalid `armoredEncryptedSecret`: %v", err),
			http.StatusBadRequest,
		)
		return
	}

	err = datastore.CreateSecret(*fpr, requestData.ArmoredEncryptedSecret, time.Now())
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(nil)
}

func parseFingerprint(fp string) (*fingerprint.Fingerprint, error) {
	if !strings.HasPrefix(fp, "OPENPGP4FPR:") {
		return nil, fmt.Errorf("missing prefix OPENPGP4FPR:")
	}

	fpr, err := fingerprint.Parse(fp[12:])
	return &fpr, err
}

func validateSecret(armoredEncryptedSecret string) error {
	return nil // TODO
}

func receiveSecretsHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}

func deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
}
