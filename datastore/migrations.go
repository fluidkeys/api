package datastore

import (
	"database/sql"
	"fmt"

	"github.com/fluidkeys/fluidkeys/team"
)

// MigrateTeamRosters moves the `roster` and `roster_signature` fields from the `teams` table
// to the `roster_versions` table (as a new, versioned row)
func MigrateTeamRosters() int {

	err := RunInTransaction(func(txn *sql.Tx) error {
		teams, err := getTeamsToMigrate(txn)
		if err != nil {
			return err
		}

		for _, dbTeam := range teams {
			err := insertVersionedRoster(txn, dbTeam)
			if err != nil {
				return fmt.Errorf("error with team %s: %v", dbTeam.UUID, err)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return 1
	}

	return 0
}

func getTeamsToMigrate(txn *sql.Tx) ([]Team, error) {
	query := `SELECT uuid, created_at, roster, roster_signature FROM teams
             WHERE roster != ''
			 AND roster != ''`

	rows, err := txn.Query(query)

	if err != nil {
		return nil, fmt.Errorf("error getting teams to migrate: %v", err)
	}
	defer rows.Close()

	teamsToMigrate := []Team{}

	for rows.Next() {
		t := Team{}
		if err := rows.Scan(&t.UUID, &t.CreatedAt, &t.Roster, &t.RosterSignature); err != nil {
			return nil, err
		}
		teamsToMigrate = append(teamsToMigrate, t)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return teamsToMigrate, nil
}

func insertVersionedRoster(txn *sql.Tx, dbTeam Team) error {
	t, err := team.Load(dbTeam.Roster, dbTeam.RosterSignature)
	if err != nil {
		return fmt.Errorf("error loading team %s: %v", dbTeam.UUID, err)
	}

	query := `INSERT INTO roster_versions (
                  team_uuid, created_at, version, roster, roster_signature
              ) VALUES ($1, $2, $3, $4, $5)`
	_, err = txn.Exec(
		query,
		dbTeam.UUID,
		dbTeam.CreatedAt,
		t.Version,
		dbTeam.Roster,
		dbTeam.RosterSignature,
	)
	if err != nil {
		return fmt.Errorf("error inserting into roster_versions: %v", err)
	}
	fmt.Printf("inserted roster version %d for team %s\n", t.Version, dbTeam.UUID)
	return nil
}
