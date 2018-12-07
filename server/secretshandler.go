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
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
	"time"
)

func sendSecretHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeJsonError(w,
			fmt.Errorf("expecting header Content-Type: application/json"),
			http.StatusBadRequest)
		return
	}

	if r.Body == nil {
		writeJsonError(w, fmt.Errorf("empty request body"), http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(r.Body)
	requestData := v1structs.SendSecretRequest{}
	err := decoder.Decode(&requestData)
	if err != nil {
		writeJsonError(w, fmt.Errorf("invalid JSON: %v", err), http.StatusBadRequest)
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
		writeJsonError(w, err, http.StatusBadRequest)
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

func getAuthorizedUserPublicKey(r *http.Request) (*pgpkey.PgpKey, error) {
	// TODO: actually authenticate a public key!
	//
	// For now anyone can "authenticate" as any public key which is
	// obviously stupid, but the impact is limited by the fact that all
	// content is encrypted to the public key.
	//
	// Look for a header like:
	// Authorization: tmpfingerprint: OPENPGP4FPR:AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB

	const prefix string = "tmpfingerprint: OPENPGP4FPR:"

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, prefix) {
		return nil, fmt.Errorf("missing Authorization header starting `tmpfingerprint: OPENPGP4FPR:`")
	}

	fpr, err := fingerprint.Parse(authHeader[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("failed to parse fingerprint: %v", err)
	}

	armoredPublicKey, found, err := datastore.GetArmoredPublicKeyForFingerprint(fpr)
	if err != nil {
		return nil, err
	} else if !found {
		return nil, fmt.Errorf("no public key found for %s", fpr)
	}

	key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)

	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}

	return key, nil
}

func parseFingerprint(fp string) (*fingerprint.Fingerprint, error) {
	if !strings.HasPrefix(fp, "OPENPGP4FPR:") {
		return nil, fmt.Errorf("missing prefix OPENPGP4FPR:")
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

	if len(armoredEncryptedSecret) > 10*1024 {
		return fmt.Errorf("secrets currently have a max size of 10K")
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
		writeJsonError(w, err, http.StatusBadRequest)
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
