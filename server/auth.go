package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/errors"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

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
		return nil, errAuthKeyNotFound
	}

	key, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)

	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}

	return key, nil
}

var errAuthKeyNotFound = fmt.Errorf("invalid authorization")
// validateDataSignedByKey checks 2 things about the given data:
// 1. that the signature is valid
// 2. that the signature came from `key`
//    - this is achieved by creating a keyring with a single key in it. if the data is
//      validly signed by *another* key it will fail, since that other key isn't in the supplied
//      keyring.
func validateDataSignedByKey(data string, armoredDetachedSignature string, key *pgpkey.PgpKey) error {
	var keyring openpgp.EntityList = []*openpgp.Entity{&key.Entity}

	_, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		strings.NewReader(data),
		strings.NewReader(armoredDetachedSignature),
	)
	if err == errors.ErrUnknownIssuer {
		return errSignedByWrongKey
	} else if err != nil {
		return errBadSignature
	}

	return nil
}
