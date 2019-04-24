package email

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/fluidkeys/api/datastore"
)

// helpCreateJoinTeam1Email holds the data required to populate the
// "helpCreateJoinTeam1HtmlBodyTemplate" email templates
type helpCreateJoinTeam1Email struct {
	InstalledAt      time.Time
	InstalledVersion string
	OptionsURL       string
}

func (e helpCreateJoinTeam1Email) Month() string {
	return e.InstalledAt.Format("January")
}

const helpCreateJoinTeam1SubjectTemplate = "Did you know Fluidkeys now works with teams?"
const helpCreateJoinTeam1HtmlBodyTemplate string = `In {{.Month}} you installed Fluidkeys {{.InstalledVersion}}, the command line app that makes PGP simple for teams. The feedback we got from early users has been great, thank you!

Since then, we've released version 1.0.

### Now you can use Fluidkeys with your team! 🎉 ###

 * Fluidkeys automatically fetches public keys for everyone in your team
 * You can store shared passwords for the team using password-store
 * You can send signed and encrypted emails more easily

### Set up a team now ###

Step 1: Upgrade Fluidkeys: www.fluidkeys.com/upgrade

Step 2: Run ` + "`fk team create`" + `

Any questions: help@fluidkeys.com

---

Choose what emails you receive from Fluidkeys:
{{.OptionsURL}}
`

// SendHelpCreateJoinTeamEmails iterates through the profiles and works out whether to send each one
// 'help_create_join_team_1' email. If so, it renders and sends the email, recording that it has
// sent it in the database.
func SendHelpCreateJoinTeamEmails() error {
	profilesNotInTeam, err := datastore.ListValidVerifiedKeysNotInTeam(nil)
	if err != nil {
		return fmt.Errorf("failed to query profiles: %v", err)
	}

	for i := range profilesNotInTeam { // send emails: `help_create_join_team_1`
		profile := profilesNotInTeam[i]

		if profile.OptoutEmailsHelpCreateJoinTeam {
			continue
		}
		// have I sent `help_create_join_team_1` to this profile already? if so, ignore.

		haveAlreadySent, err := datastore.HaveSentEmail(emailHelpCreateJoinTeam1, profile.UUID)
		if err != nil {
			log.Printf("error calling HaveSentEmail for %s: %v",
				profile.Key.Fingerprint().Hex(), err)
			continue
		}
		if haveAlreadySent {
			continue
		}

		if err = sendHelpCreateJoinTeam1Email(&profile); err != nil {
			log.Printf("error sending email: %v", err)
		}
	}

	fmt.Printf("%d keys not in a team\n", len(profilesNotInTeam))
	return nil
}

func sendHelpCreateJoinTeam1Email(profile *datastore.UserProfile) error {

	emailTemplateData := helpCreateJoinTeam1Email{
		InstalledAt:      time.Now(),              // TODO
		InstalledVersion: "0.3.0 TODO",            // TODO
		OptionsURL:       "example.com/todo TODO", // TODO
	}

	primaryEmail, err := profile.Key.Email()
	if err != nil {
		return fmt.Errorf(
			"error getting email from key %s: %v", profile.Key.Fingerprint().Hex(), err,
		)
	}

	email := email{
		to:      primaryEmail,
		from:    "Fluidkeys <help@mail.fluidkeys.com>",
		replyTo: "Fluidkeys <help@fluidkeys.com>",
	}

	if err := email.renderSubjectAndBody(emailTemplateData); err != nil {
		return fmt.Errorf("error rendering email: %v", err)
	}

	err = datastore.RunInTransaction(func(txn *sql.Tx) error {
		if err := datastore.RecordSentEmail(
			emailHelpCreateJoinTeam1,
			profile.UUID); err != nil {

			return err
		}

		fmt.Printf("SENDING EMAIL: %v\n", email)
		return nil // TODO

		if err := email.send(); err != nil {
			return fmt.Errorf("error sending mail: %v", err)
		}
		return nil
	})

	if err != nil {
		log.Printf("error sending email: %v", err)
	}

	return nil
}

const (
	emailHelpCreateJoinTeam1 = "email_help_create_join_team_1"
)
