package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
)

func createTeamHandler(w http.ResponseWriter, r *http.Request) {
	// note that the roster *could* be re-uploaded by any team member: we don't authenticate
	// the request.
	// it will only be accepted if it's correctly signed
	// see the test suite for more detail on the validations this performs

	requestData := v1structs.UpsertTeamRequest{}
	if err := decodeJsonRequest(r, &requestData); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	if requestData.TeamRoster == "" {
		writeJsonError(w, fmt.Errorf("missing teamRoster"), http.StatusBadRequest)
		return
	}

	if requestData.ArmoredDetachedSignature == "" {
		writeJsonError(w, fmt.Errorf("missing armoredDetachedSignature"), http.StatusBadRequest)
		return
	}

	apparentSignerKey, err := getAuthorizedUserPublicKey(r)
	if err == errAuthKeyNotFound {
		writeJsonError(w,
			fmt.Errorf("public key that signed the roster has not been uploaded"),
			http.StatusBadRequest)
		return
	} else if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	if err = checkRosterSignature(requestData, apparentSignerKey); err != nil {
		log.Printf("roster signature verification failed: %v", err)
		writeJsonError(w, fmt.Errorf("signature verification failed"), http.StatusBadRequest)
		return
	}

	team, err := team.Parse(strings.NewReader(requestData.TeamRoster))
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	if err := team.Validate(); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	person, err := team.GetPersonForFingerprint(apparentSignerKey.Fingerprint())
	if err != nil {
		writeJsonError(w,
			fmt.Errorf("signing key's fingerprint isn't listed in roster"), http.StatusBadRequest)
		return
	}

	err = datastore.RunInTransaction(func(txn *sql.Tx) error {

		if verified, err := datastore.QueryEmailVerifiedForFingerprint(
			txn, person.Email, apparentSignerKey.Fingerprint()); err != nil {

			return fmt.Errorf("error querying email verification: %v", err)
		} else if !verified {

			return fmt.Errorf("signing key's email listed in roster is unverified")
		}

		if exists, err := datastore.TeamExists(txn, team.UUID); err != nil {
			return fmt.Errorf("error querying for team: %v", err)
		} else if exists {
			return fmt.Errorf("team with UUID %s already exists", team.UUID)
		}

		team := datastore.Team{
			UUID:            team.UUID,
			Roster:          requestData.TeamRoster,
			RosterSignature: requestData.ArmoredDetachedSignature,
			CreatedAt:       time.Now(),
		}

		if err := datastore.CreateTeam(txn, team); err != nil {
			return fmt.Errorf("error creating team: %v", err)
		}

		return nil
	})

	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(nil)
}

func checkRosterSignature(requestData v1structs.UpsertTeamRequest, signerKey *pgpkey.PgpKey) error {
	var keyring openpgp.EntityList = []*openpgp.Entity{&signerKey.Entity}

	_, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		strings.NewReader(requestData.TeamRoster),
		strings.NewReader(requestData.ArmoredDetachedSignature),
	)
	return err
}
