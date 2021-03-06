package server

import (
	"encoding/json"
	"fmt"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/policy"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
	"time"
)

func sendSecretHandler(w http.ResponseWriter, r *http.Request) {
	requestData := v1structs.SendSecretRequest{}

	if err := decodeJsonRequest(r, &requestData); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	recipientFingerprint, err := parseFingerprint(requestData.RecipientFingerprint)
	if err != nil {
		writeJsonError(w,
			fmt.Errorf("invalid `recipientFingerprint`: %v", err),
			http.StatusBadRequest,
		)
		return
	}

	err = validateSecret(requestData.ArmoredEncryptedSecret, *recipientFingerprint)
	if err != nil {
		writeJsonError(w,
			fmt.Errorf("invalid `armoredEncryptedSecret`: %v", err),
			http.StatusBadRequest,
		)
		return
	}

	_, err = datastore.CreateSecret(*recipientFingerprint, requestData.ArmoredEncryptedSecret, time.Now())
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(nil)
}

func listSecretsHandler(w http.ResponseWriter, r *http.Request) {
	myPublicKey, err := getAuthorizedUserPublicKey(r)

	if err != nil {
		writeJsonError(w, err, http.StatusUnauthorized)
		return
	}

	responseData := v1structs.ListSecretsResponse{}

	secrets, err := datastore.GetSecrets(myPublicKey.Fingerprint())
	if err != nil {
		writeJsonError(w, fmt.Errorf("error getting secrets: %v", err), http.StatusInternalServerError)
		return
	}

	responseData.Secrets = make([]v1structs.Secret, 0)

	for _, s := range secrets {
		encryptedMetadata, err := encryptSecretMetadata(
			v1structs.SecretMetadata{
				SecretUUID: s.SecretUUID,
			},
			myPublicKey,
		)

		if err != nil {
			writeJsonError(w, fmt.Errorf("failed to encrypt metadata: %v", err), http.StatusInternalServerError)
			return
		}

		secret := v1structs.Secret{
			EncryptedContent:  s.ArmoredEncryptedSecret,
			EncryptedMetadata: encryptedMetadata,
		}

		responseData.Secrets = append(responseData.Secrets, secret)
	}

	writeJsonResponse(w, responseData)
}

func encryptSecretMetadata(metadata v1structs.SecretMetadata, key *pgpkey.PgpKey) (string, error) {
	jsonOut, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to encode JSON: %v", err)
	}

	encrypted, err := encryptStringToArmor(string(jsonOut), key)

	if err != nil {
		return "", fmt.Errorf("failed to encrypt to key: %v", err)
	}

	return encrypted, nil
}

func parseFingerprint(fp string) (*fingerprint.Fingerprint, error) {
	if !strings.HasPrefix(fp, "OPENPGP4FPR:") {
		return nil, fmt.Errorf("missing prefix `OPENPGP4FPR:`")
	}

	fpr, err := fingerprint.Parse(fp[12:])
	return &fpr, err
}

func validateSecret(armoredEncryptedSecret string, recipientFingerprint fingerprint.Fingerprint) error {
	if armoredEncryptedSecret == "" {
		return fmt.Errorf("empty string")
	}

	block, err := armor.Decode(strings.NewReader(armoredEncryptedSecret))
	if err != nil {
		return fmt.Errorf("error decoding ASCII armor: %s", err)
	}

	if len(armoredEncryptedSecret) > 2*policy.SecretMaxSizeBytes {
		return fmt.Errorf("secrets currently have a max size of %d bytes",
			policy.SecretMaxSizeBytes)
	}

	pkt1, err := packet.Read(block.Body)
	if err != nil {
		return fmt.Errorf("error reading Public-Key Encrypted Session Key Packet (tag 1): %v", err)
	} else if _, ok := pkt1.(*packet.EncryptedKey); !ok {
		return fmt.Errorf("message did not start with Public-Key Encrypted Session Key Packet (tag 1)")
	}

	pkt2, err := packet.Read(block.Body)
	if err != nil {
		return fmt.Errorf(
			"error reading Symmetrically Encrypted Integrity "+
				"Protected Data Packet (tag 18): %v", err)
	} else if _, ok := pkt2.(*packet.SymmetricallyEncrypted); !ok {
		return fmt.Errorf(
			"second packet was not Sym. Encrypted Integrity " +
				"Protected Data Packet (tag 18")
	}

	// TODO: test there are no additional packets
	return nil
}

func deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	myPublicKey, err := getAuthorizedUserPublicKey(r)

	if err != nil {
		writeJsonError(w, err, http.StatusUnauthorized)
		return
	}

	secretUUID, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		writeJsonError(w, fmt.Errorf("error parsing UUID: %v", err), http.StatusBadRequest)
		return
	}

	found, err := datastore.DeleteSecret(secretUUID, myPublicKey.Fingerprint())
	if err != nil {
		writeJsonError(w, fmt.Errorf("error deleting secret: %v", err), http.StatusInternalServerError)
		return
	} else if !found {
		writeJsonError(w, fmt.Errorf("no secret matching that UUID and public key"), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write(nil)
}
