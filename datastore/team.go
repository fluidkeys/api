package datastore

import (
	"database/sql"
	"fmt"
	"time"

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

// CreateTeam creates a team in the database.
// If a team already exists with team.UUID it returns an error
func CreateTeam(txn *sql.Tx, team Team) error {
	query := `INSERT INTO teams (uuid, created_at, roster, roster_signature)
	          VALUES ($1, $2, $3, $4)`

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

// Team represents a team in the database
type Team struct {
	UUID   uuid.UUID
	Roster string

	// RosterSignature is the ASCII-armored, detached signature of the Roster
	RosterSignature string
	CreatedAt       time.Time
}

// ErrNotFound indicates that the requested item wasn't found in the database (but the query was
// successful)
var ErrNotFound = fmt.Errorf("not found")
