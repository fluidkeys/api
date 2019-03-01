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
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
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

func getTeamHandler(w http.ResponseWriter, r *http.Request) {
	teamUUID, err := uuid.FromString(mux.Vars(r)["teamUUID"])
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	dbTeam, err := datastore.GetTeam(nil, teamUUID)
	if err == datastore.ErrNotFound {
		writeJsonError(w, err, http.StatusNotFound)
		return

	} else if err != nil {
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	}

	// parse the roster to get the team name
	team, err := team.Parse(strings.NewReader(dbTeam.Roster))
	if err != nil {
		writeJsonError(w,
			fmt.Errorf("failed to parse name from team roster"),
			http.StatusInternalServerError)
		return
	}

	responseData := v1structs.GetTeamResponse{
		Name: team.Name,
	}

	writeJsonResponse(w, responseData)
}

func createRequestToJoinTeamHandler(w http.ResponseWriter, r *http.Request) {
	teamUUID, err := uuid.FromString(mux.Vars(r)["teamUUID"])
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	requestKey, err := getAuthorizedUserPublicKey(r)
	if err == errAuthKeyNotFound {
		writeJsonError(w,
			fmt.Errorf("public key for fingerprint has not been uploaded"),
			http.StatusBadRequest)
		return
	} else if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	requestData := v1structs.RequestToJoinTeamRequest{}
	if err := decodeJsonRequest(r, &requestData); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	if requestData.TeamEmail == "" {
		writeJsonError(w, fmt.Errorf("missing teamEmail"), http.StatusBadRequest)
		return
	}

	err = datastore.RunInTransaction(func(txn *sql.Tx) error {
		if verified, err := datastore.QueryEmailVerifiedForFingerprint(
			txn, requestData.TeamEmail, requestKey.Fingerprint()); err != nil {
			return fmt.Errorf("error checking verification: %v", err)
		} else if !verified {
			return fmt.Errorf("key is not verified for email")
		}

		dbTeam, err := datastore.GetTeam(txn, teamUUID)
		if err == datastore.ErrNotFound {
			return fmt.Errorf("team not found")
		} else if err != nil {
			return fmt.Errorf("error fetching team: %v", err)
		}

		existingRequest, err := datastore.GetRequestToJoinTeam(txn, teamUUID, requestData.TeamEmail)
		if err != nil && err != datastore.ErrNotFound {
			return fmt.Errorf("error looking for existing request: %v", err)
		}

		if existingRequest != nil {
			if existingRequest.Fingerprint == requestKey.Fingerprint() {
				// got an existing, identical request. rather than creating a new one, just return the
				// UUID of the existing one
				return errIdenticalRequestAlreadyExists
			}

			// got an existing request for the same {team, email} combination but with a different
			// fingerprint. reject it.
			return errConflictingRequestAlreadyExists
		}

		_, err = datastore.CreateRequestToJoinTeam(
			txn, dbTeam.UUID, requestData.TeamEmail, requestKey.Fingerprint(), time.Now())
		return nil
	})

	switch err {
	case nil:
		w.WriteHeader(http.StatusCreated)
		w.Write(nil)
		return

	case errIdenticalRequestAlreadyExists:
		writeJsonError(w,
			fmt.Errorf("already got request to join team with that email and fingerprint"),
			http.StatusConflict)
		return

	case errConflictingRequestAlreadyExists:
		writeJsonError(w,
			fmt.Errorf("got existing request for conflicting-example@example.com to join that "+
				"team with a different fingerprint"),
			http.StatusConflict)
		return

	default:
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	}

}

func deleteRequestToJoinTeamHandler(w http.ResponseWriter, r *http.Request) {
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

var errIdenticalRequestAlreadyExists = fmt.Errorf(
	"request to join team already exists with the same email and fingerprint")

var errConflictingRequestAlreadyExists = fmt.Errorf(
	"request to join team already exists for that email with a different fingerprint")
