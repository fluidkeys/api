package datastore

import (
	"database/sql"
	"fmt"
	"time"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

// GetTeam returns a Team from the database
func GetTeam(txn *sql.Tx, teamUUID uuid.UUID) (*Team, error) {
	query := `SELECT uuid,
                     created_at,
					 roster,
					 roster_signature
		  FROM teams
		  WHERE uuid=$1`

	team := Team{}

	err := transactionOrDatabase(txn).QueryRow(query, teamUUID).Scan(
		&team.UUID,
		&team.CreatedAt,
		&team.Roster,
		&team.RosterSignature,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound

	} else if err != nil {
		return nil, err
	}

	return &team, nil
}

// TeamExists returns true if the team with the given UUID already exists in the database
func TeamExists(txn *sql.Tx, teamUUID uuid.UUID) (bool, error) {
	_, err := GetTeam(txn, teamUUID)
	switch err {
	case nil:
		return true, nil

	case ErrNotFound:
		return false, nil

	default:
		return false, err
	}
}

// UpsertTeam creates a team in the database.
// If a team already exists with team.UUID it updates the team.
func UpsertTeam(txn *sql.Tx, team Team) error {
	query := `INSERT INTO teams (uuid, created_at, roster, roster_signature)
	          VALUES ($1, $2, $3, $4)
              ON CONFLICT (uuid) DO UPDATE
              SET roster           = EXCLUDED.roster,
                  roster_signature = EXCLUDED.roster_signature`

	// query := `INSERT INTO teams (uuid, created_at, roster, roster_signature)
	//           VALUES ($1, $2)
	// 	  ON CONFLICT (uid) DO UPDATE
	// 	      SET armored_public_key=EXCLUDED.armored_public_key`

	_, err := transactionOrDatabase(txn).Exec(
		query,
		team.UUID,
		team.CreatedAt,
		team.Roster,
		team.RosterSignature,
	)

	return err
}

// DeleteTeam deletes the team with the given UUID and returns true if it was deleted, or false
// if the team was not found.
func DeleteTeam(txn *sql.Tx, teamUUID uuid.UUID) (found bool, err error) {
	query := `DELETE FROM teams WHERE uuid = $1`

	result, err := transactionOrDatabase(txn).Exec(query, teamUUID)
	if err != nil {
		return false, err
	}

	numRowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if numRowsAffected < 1 {
		return false, nil // not found (but no error)
	}

	return true, nil // found and deleted
}

// CreateRequestToJoinTeam creates a new request to add the given email and key fingerprint to
// the team.
// It's only allowed to have a single request per {team, email} pair. Attempts to create a second
// request for the same {team, email} but *different* fingerprint will fail.
func CreateRequestToJoinTeam(
	txn *sql.Tx, teamUUID uuid.UUID,
	email string, fingerprint fpr.Fingerprint, now time.Time) (*uuid.UUID, error) {

	if exists, err := TeamExists(txn, teamUUID); err != nil {
		return nil, fmt.Errorf("error checking if team exists: %v", err)
	} else if !exists {
		return nil, ErrNotFound
	}

	existingRequest, err := GetRequestToJoinTeam(txn, teamUUID, email)
	if err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("error looking for existing request: %v", err)
	}

	if existingRequest != nil && existingRequest.Fingerprint == fingerprint {
		// got an existing, identical request. rather than creating a new one, just return the
		// UUID of the existing one
		return &existingRequest.UUID, nil
	} else if existingRequest != nil && existingRequest.Fingerprint != fingerprint {
		// got an existing request for the same {team, email} combination but with a different
		// fingerprint. reject it.
		return nil, fmt.Errorf("existing request for {team, email}")
	}

	query := `INSERT INTO team_join_requests (uuid, created_at, team_uuid, email, fingerprint)
	          VALUES ($1, $2, $3, $4, $5)`

	newRequestUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	_, err = transactionOrDatabase(txn).Exec(
		query,
		newRequestUUID,
		now,
		teamUUID,
		email,
		dbFormat(fingerprint),
	)

	return &newRequestUUID, err
}

// GetRequestToJoinTeam searches for an existing request for the given team UUID and email
// address combination.
func GetRequestToJoinTeam(txn *sql.Tx, teamUUID uuid.UUID, email string) (
	*RequestToJoinTeam, error) {

	query := `SELECT uuid, created_at, email, fingerprint
		        FROM team_join_requests
	            WHERE team_uuid=$1
	            AND email=$2`

	request := RequestToJoinTeam{}

	var fingerprintString string

	err := transactionOrDatabase(txn).QueryRow(query, teamUUID, email).Scan(
		&request.UUID,
		&request.CreatedAt,
		&request.Email,
		&fingerprintString,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound

	} else if err != nil {
		return nil, err
	}

	if request.Fingerprint, err = parseDbFormat(fingerprintString); err != nil {
		return nil, fmt.Errorf("got bad fingerprint from database: %v", fingerprintString)
	}

	return &request, nil
}

// DeleteRequestToJoinTeam deletes the given request to join team (by UUID)
func DeleteRequestToJoinTeam(txn *sql.Tx, requestUUID uuid.UUID) (found bool, err error) {
	query := `DELETE FROM team_join_requests WHERE uuid=$1`

	result, err := transactionOrDatabase(txn).Exec(query, requestUUID)
	if err != nil {
		return false, err
	}

	numRowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if numRowsAffected < 1 {
		return false, nil // not found (but no error)
	}

	return true, nil // found and deleted
}

// GetRequestsToJoinTeam returns a slice of RequestToJoinTeams.
func GetRequestsToJoinTeam(txn *sql.Tx, teamUUID uuid.UUID) ([]RequestToJoinTeam, error) {
	query := `SELECT uuid, created_at, email, fingerprint
		        FROM team_join_requests
	            WHERE team_uuid=$1`

	rows, err := transactionOrDatabase(txn).Query(query, teamUUID)
	if err != nil {
		return nil, err
	}

	requestsToJoinTeam := make([]RequestToJoinTeam, 0)

	defer rows.Close()
	for rows.Next() {
		var requestToJoinTeam RequestToJoinTeam
		var fingerprintString string
		if err := rows.Scan(
			&requestToJoinTeam.UUID,
			&requestToJoinTeam.CreatedAt,
			&requestToJoinTeam.Email,
			&fingerprintString,
		); err != nil {
			return nil, err
		}
		if requestToJoinTeam.Fingerprint, err = parseDbFormat(fingerprintString); err != nil {
			return nil, fmt.Errorf("got bad fingerprint from database: %v", fingerprintString)
		}
		requestsToJoinTeam = append(requestsToJoinTeam, requestToJoinTeam)
	}
	err = rows.Err()

	if err != nil {
		return nil, err
	}

	return requestsToJoinTeam, nil
}

// Team represents a team in the database
type Team struct {
	UUID   uuid.UUID
	Roster string

	// RosterSignature is the ASCII-armored, detached signature of the Roster
	RosterSignature string
	CreatedAt       time.Time
}

// RequestToJoinTeam represents a request to join a team in the database.
type RequestToJoinTeam struct {
	UUID        uuid.UUID
	CreatedAt   time.Time
	Email       string
	Fingerprint fpr.Fingerprint
}

// ErrNotFound indicates that the requested item wasn't found in the database (but the query was
// successful)
var ErrNotFound = fmt.Errorf("not found")
