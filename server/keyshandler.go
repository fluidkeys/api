package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	email := mux.Vars(r)["email"]

	responseData := v1structs.GetPublicKeyResponse{}

	armoredPublicKey, found, err := datastore.GetArmoredPublicKeyForEmail(email)
	if err != nil {
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	} else if !found {
		writeJsonError(
			w,
			fmt.Errorf("couldn't find a public key for email address '%s'", email),
			http.StatusNotFound,
		)
		return
	}

	responseData.ArmoredPublicKey = armoredPublicKey
	writeJsonResponse(w, responseData)
}

func upsertPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	requestData := v1structs.UpsertPublicKeyRequest{}

	if err := decodeJsonRequest(r, &requestData); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	publicKey, err := pgpkey.LoadFromArmoredPublicKey(requestData.ArmoredPublicKey)
	if err != nil {
		writeJsonError(w, fmt.Errorf("error loading public key: %v", err), http.StatusBadRequest)
		return
	}

	singleUseUUID, err := validateSignedData(requestData.ArmoredSignedJSON, requestData.ArmoredPublicKey, publicKey)
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	_, encrypted, err := generateAndEncryptPassword(publicKey)
	if err != nil {
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	}

	err = datastore.UpsertPublicKey(requestData.ArmoredPublicKey)
	if err != nil {
		writeJsonError(w, fmt.Errorf("error storing key: %v", err), http.StatusInternalServerError)
		return
	}

	err = datastore.StoreSingleUseNumber(*singleUseUUID, time.Now())
	if err != nil {
		writeJsonError(w, fmt.Errorf("error storing key: %v", err), http.StatusInternalServerError)
		return
	}

	// TODO: store new basic auth password

	responseData := v1structs.UpsertPublicKeyResponse{
		ArmoredEncryptedBasicAuthPassword: encrypted,
	}

	writeJsonResponse(w, responseData)
}

func validateSignedData(armoredSignedData string, armoredPublicKey string, publicKey *pgpkey.PgpKey) (*uuid.UUID, error) {
	verifiedJSON, err := verify([]byte(armoredSignedData), publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify: %v", err)
	}

	signedData := v1structs.UpsertPublicKeySignedData{}

	err = json.NewDecoder(bytes.NewReader(verifiedJSON)).Decode(&signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}

	if !within24Hours(time.Now(), signedData.Timestamp) {
		// TODO: log possible attack
		return nil, fmt.Errorf("timestamp is not within 24 hours of server time")
	}

	singleUseUUID, err := uuid.FromString(signedData.SingleUseUUID)
	if err != nil {
		return nil, fmt.Errorf("bad SingleUseUUID: %v", err)
	}

	if err := datastore.VerifySingleUseNumberNotStored(singleUseUUID); err != nil {
		// TODO: log possible attack
		return nil, fmt.Errorf("bad SingleUseUUID: %v", err)
	}

	givenSHA256, err := hex.DecodeString(signedData.PublicKeySHA256)
	if err != nil {
		// TODO: log possible attack
		return nil, fmt.Errorf("bad SHA256: %v", err)
	}

	calculatedSHA256 := sha256.Sum256([]byte(armoredPublicKey))
	if !hashesEqual(givenSHA256, calculatedSHA256[:]) {
		// TODO: log possible attack
		return nil, fmt.Errorf("mismatching public key SHA256")
	}
	return &singleUseUUID, nil
}

func generateAndEncryptPassword(publicKey *pgpkey.PgpKey) (newPassword string, encrypted string, err error) {
	if newUUID, err := uuid.NewV4(); err != nil {
		return "", "", fmt.Errorf("error making UUID: %v", err)
	} else {
		newPassword = newUUID.String()
	}

	encryptedPassword, err := encryptStringToArmor(newPassword, publicKey)
	if err != nil {
		return "", "", fmt.Errorf("error encrypting to key: %v", err)
	}
	return newPassword, encryptedPassword, nil
}

func within24Hours(a, b time.Time) bool {
	const twentyFourHours = time.Hour * time.Duration(24)

	timeDelta := a.Sub(b)

	return -twentyFourHours <= timeDelta && timeDelta < twentyFourHours
}

func hashesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
