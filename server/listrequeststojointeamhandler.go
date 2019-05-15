package server

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

func listRequestsToJoinTeamHandler(w http.ResponseWriter, r *http.Request) {
	requesterKey, err := getAuthorizedUserPublicKey(r)
	if err == errAuthKeyNotFound {
		writeJsonError(w,
			fmt.Errorf("public key that signed the roster has not been uploaded"),
			http.StatusBadRequest)
		return
	} else if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	teamUUID, err := uuid.FromString(mux.Vars(r)["teamUUID"])
	if err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	var requestsToJoinTeam = []datastore.RequestToJoinTeam{}

	err = datastore.RunInTransaction(func(txn *sql.Tx) error {
		dbTeam, err := datastore.GetTeam(nil, teamUUID)
		if err != nil {
			return err
		}

		t, err := team.Load(dbTeam.Roster, dbTeam.RosterSignature)
		if err != nil {
			return fmt.Errorf("error loading team from db: %v", err)
		}

		meInTeam, err := t.GetPersonForFingerprint(requesterKey.Fingerprint())
		if err != nil || !meInTeam.IsAdmin {
			return errNotAnAdminInExistingTeam
		}

		requestsToJoinTeam, err = datastore.GetRequestsToJoinTeam(txn, teamUUID)
		if err != nil {
			return fmt.Errorf("error querying for requests to join team: %v", err)
		}
		return nil
	})

	switch err {
	case nil: // no error
		break

	case datastore.ErrNotFound:
		writeJsonError(w, fmt.Errorf("team not found"), http.StatusNotFound)
		return

	case errBadSignature:
		writeJsonError(w,
			fmt.Errorf("team roster signature problem: %v", err),
			http.StatusInternalServerError,
		)
		return

	case errNotAnAdminInExistingTeam:
		writeJsonError(w,
			fmt.Errorf("only team admins can see requests to join the team"),
			http.StatusForbidden)
		return

	default:
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	}

	responses := []v1structs.RequestToJoinTeam{}

	for _, request := range requestsToJoinTeam {
		responses = append(responses, v1structs.RequestToJoinTeam{
			UUID:        request.UUID.String(),
			Fingerprint: request.Fingerprint.Uri(),
			Email:       request.Email,
		})
	}

	responseData := v1structs.ListRequestsToJoinTeamResponse{
		Requests: responses,
	}

	writeJsonResponse(w, responseData)
}
