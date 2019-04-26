package email

import (
	"fmt"
	"time"

	"github.com/fluidkeys/api/datastore"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
)

// SendKeyExpiresEmails sends expiry reminders for keys expiring in 14, 7, 3 days
func SendKeyExpiresEmails() error {
	const from = "Fluidkeys <help@mail.fluidkeys.com>"
	const replyTo = "Fluidkeys <help@fluidkeys.com>"

	keysExpiring, err := datastore.ListKeysExpiring()
	if err != nil {
		return fmt.Errorf("error calling datastore.ListKeysKeysExpiring: %v", err)
	}

	var numSent, numErrors, numAlreadySent int

	for i := range keysExpiring {
		daysUntilExpiry := keysExpiring[i].DaysUntilExpiry
		userProfile := keysExpiring[i].UserProfile
		key := userProfile.Key
		primaryEmail := keysExpiring[i].PrimaryEmail

		switch daysUntilExpiry {
		case 3:

			templateData := helpKeyExpires3Days{
				Email:       primaryEmail,
				Fingerprint: key.Fingerprint(),
			}

			// rate-limit this type of email to once every 7 days. this allows us to run this
			// query multiple times on the same day without sending duplicate emails.
			rateLimit := time.Duration(7*24) * time.Hour
			err := sendEmail(
				userProfile.UUID,
				templateData,
				primaryEmail,
				from,
				replyTo,
				&rateLimit)

			if err == errRateLimit {
				numAlreadySent++
				continue
			} else if err != nil {
				fmt.Printf("error sending email: %v\n", err)
				numErrors++
				continue
			}

			numSent++

			fmt.Printf(
				"sent 3-day reminder for %s to %s\n", key.Fingerprint().Hex(), primaryEmail,
			)

		default:
			continue
		}
	}

	fmt.Printf("key expiring emails: %d sent, %d failed, %d already sent (rate-limited).\n",
		numSent, numErrors, numAlreadySent)

	return nil
}

// helpKeyExpires3Days holds the data required to populate the
// "help_key_expires_3_days" email template
type helpKeyExpires3Days struct {
	Email       string
	Fingerprint fpr.Fingerprint
}

func (e helpKeyExpires3Days) ID() string { return "help_key_expires_3_days" }
func (e helpKeyExpires3Days) RenderInto(eml *email) (err error) {
	eml.subject = helpKeyExpires3DaysSubject
	eml.htmlBody, err = render(helpKeyExpires3DaysBodyTemplate, e)
	return err
}

const helpKeyExpires3DaysSubject = "❌ PGP key expiring: we'll delete it in 3 days"
const helpKeyExpires3DaysBodyTemplate string = `You installed Fluidkeys[0] and uploaded a public key to our server. Great!

Normally, Fluidkeys extends and uploads your public key automatically to save you the hassle.

It looks like something stopped working on your machine as we don't see an updated key on our server.

In 3 days your key will expire and we'll delete it from our server.

Email: {{.Email}}
Fingerprint: {{.Fingerprint}}


## Extend and upload your key

You can extend and upload your key now by running:

fk key maintain
fk key upload

It should ask you to switch on automatic maintenance so that this doesn't happen again.

Any problems, hit reply and we'll help you out.


## We'll delete your data automatically

If you don't extend your key, we'll automatically delete your public key from our server. This includes your email address so you won't receive any more automated emails like this one.


[0] https://www.fluidkeys.com

Don't want to receive expiry reminders? Hit reply and let us know.  
`

// -------------------- help_key_expires_7_days --------------------
type helpKeyExpires7Days struct {
	Email       string
	Fingerprint fpr.Fingerprint
}

func (e helpKeyExpires7Days) ID() string { return "help_key_expires_7_days" }
func (e helpKeyExpires7Days) RenderInto(eml *email) (err error) {
	eml.subject = helpKeyExpires7DaysSubject
	eml.htmlBody, err = render(helpKeyExpires7DaysBodyTemplate, e)
	return err
}

const helpKeyExpires7DaysSubject = "⏰ Your PGP key expires in 7 days: extend it now to continue using Fluidkeys"
const helpKeyExpires7DaysBodyTemplate string = `
You installed Fluidkeys[0] and uploaded a public key to our server. Great!

Normally, Fluidkeys extends and uploads your public key automatically to save you the hassle.

It looks like something stopped working on your machine as we don't see an updated key on our server.

In 7 days your key will expire and Fluidkeys will stop working.

Email: {{.Email}}
Key: {{.Fingerprint}}


## Extend and upload your key

You can extend and upload your key now by running:

fk key maintain
fk key upload

It should ask you to switch on automatic maintenance so that this doesn't happen again.

Any problems, hit reply and we'll help you out.


## We'll delete your data automatically

If you don't extend your key, we'll automatically delete your public key from our server. This includes your email address so you won't receive any more automated emails like this one.


[0] https://www.fluidkeys.com

Don't want to receive expiry reminders? Hit reply and let us know.`

// -------------------- help_key_expires_14_days --------------------
type helpKeyExpires14Days struct {
	Email       string
	Fingerprint fpr.Fingerprint
}

func (e helpKeyExpires14Days) ID() string { return "help_key_expires_14_days" }
func (e helpKeyExpires14Days) RenderInto(eml *email) (err error) {
	eml.subject = helpKeyExpires14DaysSubject
	eml.htmlBody, err = render(helpKeyExpires14DaysBodyTemplate, e)
	return err
}

const helpKeyExpires14DaysSubject = "⏰ Your PGP key expires in 14 days: extend it now"
const helpKeyExpires14DaysBodyTemplate string = `You installed Fluidkeys[0] and uploaded a public key to our server. Fantastic!

Normally, Fluidkeys extends and uploads your public key automatically to save you the hassle.

It looks like something stopped working on your machine as we don't see an updated key on our server.

In 14 days your key will expire and Fluidkeys will stop working.

Email: {{.Email}}
Key: {{.Fingerprint}}

## Extend and upload your key

You can extend and upload your key now by running:

fk key maintain
fk key upload

It should ask you to switch on automatic maintenance so that this doesn't happen again.

Any problems, hit reply and we'll help you out.


[0] https://www.fluidkeys.com

Don't want to receive expiry reminders? Hit reply and let us know.`
