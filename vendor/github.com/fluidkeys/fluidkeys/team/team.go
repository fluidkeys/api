package team

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
	"github.com/natefinch/atomic"
)

// LoadTeams scans the fluidkeys/teams directory for subdirectories, enters them and tries to load
// roster.toml
// Returns a slice of Team
func LoadTeams(fluidkeysDirectory string) ([]Team, error) {
	teamRosters, err := findTeamRosters(getTeamDirectory(fluidkeysDirectory))
	if err != nil {
		return nil, err
	}

	teams := []Team{}
	for _, teamRoster := range teamRosters {
		log.Printf("loading team roster %s\n", teamRoster)
		team, err := loadTeamRoster(teamRoster)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %v", teamRoster, err)
		}
		teams = append(teams, *team)
	}
	return teams, nil
}

// SignAndSave validates the given team then tries to make a toml team roster in a subdirectory of
// the given directory with accompanying signature from the signing key.
// If successful, it returns the roster and signature as strings.
func SignAndSave(team Team, fluidkeysDirectory string, signingKey *pgpkey.PgpKey) (
	roster string, signature string, err error) {

	err = team.Validate()
	if err != nil {
		return "", "", fmt.Errorf("invalid team: %v", err)
	}

	if !team.IsAdmin(signingKey.Fingerprint()) {
		return "", "", fmt.Errorf("can't sign with key %s that's not an admin of the team",
			signingKey.Fingerprint())
	}

	rosterDirectory := filepath.Join(
		getTeamDirectory(fluidkeysDirectory), // ~/.config/fluidkeys/teams
		team.subDirectory(),                  // fluidkeys-inc-4367436743
	)
	if err = os.MkdirAll(rosterDirectory, 0700); err != nil {
		return "", "", fmt.Errorf("failed to make directory %s", rosterDirectory)
	}

	roster, err = team.Roster()
	if err != nil {
		return "", "", err
	}

	rosterFilename := filepath.Join(rosterDirectory, "roster.toml")
	signatureFilename := rosterFilename + ".asc"

	signature, err = signingKey.MakeArmoredDetachedSignature([]byte(roster))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign team roster: %v", err)
	}

	if err = atomic.WriteFile(rosterFilename, bytes.NewBufferString(roster)); err != nil {
		return "", "", fmt.Errorf("failed write team roster: %v", err)
	}
	err = atomic.WriteFile(signatureFilename, bytes.NewBufferString(signature))
	if err != nil {
		return "", "", fmt.Errorf("failed write signature: %v", err)
	}

	return roster, signature, nil
}

// Validate asserts that the team roster has no email addresses or fingerprints that are
// listed more than once.
func (t *Team) Validate() error {
	if t.UUID == uuid.Nil {
		return fmt.Errorf("invalid roster: invalid UUID")
	}

	emailsSeen := map[string]bool{} // look for multiple email addresses
	for _, person := range t.People {
		if _, alreadySeen := emailsSeen[person.Email]; alreadySeen {
			return fmt.Errorf("email listed more than once: %s", person.Email)
		}
		emailsSeen[person.Email] = true
	}

	fingerprintsSeen := map[fpr.Fingerprint]bool{}
	for _, person := range t.People {
		if _, alreadySeen := fingerprintsSeen[person.Fingerprint]; alreadySeen {
			return fmt.Errorf("fingerprint listed more than once: %s", person.Fingerprint)
		}
		fingerprintsSeen[person.Fingerprint] = true
	}

	var numberOfAdmins int
	for _, person := range t.People {
		if person.IsAdmin {
			numberOfAdmins++
		}
	}
	if numberOfAdmins == 0 {
		return fmt.Errorf("team has no administrators")
	}
	return nil
}

// IsAdmin takes a given fingerprint and returns whether they are an administor of the team
func (t Team) IsAdmin(fingerprint fpr.Fingerprint) bool {
	for _, person := range t.People {
		if person.IsAdmin && person.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// GetPersonForFingerprint takes a fingerprint and returns the person in the team with the
// matching fingperint.
func (t *Team) GetPersonForFingerprint(fingerprint fpr.Fingerprint) (*Person, error) {
	for _, person := range t.People {
		if person.Fingerprint == fingerprint {
			return &person, nil
		}
	}

	return nil, fmt.Errorf("person not found")
}

func getTeamDirectory(fluidkeysDirectory string) string {
	return filepath.Join(fluidkeysDirectory, "teams")
}

func findTeamRosters(directory string) ([]string, error) {
	teamSubdirs, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	teamRosters := []string{}

	for _, teamSubDir := range teamSubdirs {
		if !teamSubDir.IsDir() {
			continue
		}

		teamRoster := filepath.Join(directory, teamSubDir.Name(), "roster.toml")
		// TODO: also look for teamRoster.asc and validate the signature

		if fileExists(teamRoster) {
			teamRosters = append(teamRosters, teamRoster)
		} else {
			log.Printf("missing %s", teamRoster)
		}
	}
	return teamRosters, nil
}

func loadTeamRoster(filename string) (*Team, error) {
	reader, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", filename, err)
	}

	team, err := Parse(reader)
	if err != nil {
		return nil, err
	}

	err = team.Validate()
	if err != nil {
		return nil, fmt.Errorf("error validating team: %v", err)
	}

	return team, nil
}

func fileExists(filename string) bool {
	if fileinfo, err := os.Stat(filename); err == nil {
		// path/to/whatever exists
		return !fileinfo.IsDir()
	}
	return false
}

// Team represents a group of people in Fluidkeys
type Team struct {
	UUID   uuid.UUID `toml:"uuid"`
	Name   string    `toml:"name"`
	People []Person  `toml:"person"`
}

// Fingerprints returns the key fingerprints for all people in the team
func (t *Team) Fingerprints() []fpr.Fingerprint {
	fingerprints := []fpr.Fingerprint{}

	for _, person := range t.People {
		fingerprints = append(fingerprints, person.Fingerprint)
	}
	return fingerprints
}

// Person represents a human team member
type Person struct {
	Email       string          `toml:"email"`
	Fingerprint fpr.Fingerprint `toml:"fingerprint"`
	IsAdmin     bool            `toml:"is_admin"`
}

// RequestToJoinTeam represents a request to join a team
type RequestToJoinTeam struct {
	UUID        uuid.UUID
	Email       string
	Fingerprint fpr.Fingerprint
}
