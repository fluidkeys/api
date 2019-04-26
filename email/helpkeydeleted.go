package email

import (
	"log"
	"time"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

// SendKeyExpiredDeleted sends an email to the given address informing them that their
// key expired and was deleted.
func SendKeyExpiredDeleted(
	userProfileUUID uuid.UUID,
	email string,
	fingerprint fpr.Fingerprint) error {

	templateData := helpKeyExpiredDeleted{
		Email:       email,
		Fingerprint: fingerprint,
	}

	const from = "Fluidkeys <help@mail.fluidkeys.com>"
	const replyTo = "Fluidkeys <help@fluidkeys.com>"

	// rate-limit this type of email to once per day. this allows us to run this
	// query multiple times on the same day without sending duplicate emails.
	rateLimit := time.Duration(24) * time.Hour
	err := sendEmail(
		userProfileUUID,
		templateData,
		email,
		from,
		replyTo,
		&rateLimit)

	if err == errRateLimit {
		log.Printf("%s hit rate limit on SendKeyExpiredDeleted (shouldn't happen!)",
			fingerprint.Hex())
		return err
	}
	if err != nil {
		return err
	}
	return nil
}

// ---------- help_key_expired_deleted ----------
type helpKeyExpiredDeleted struct {
	Email       string
	Fingerprint fpr.Fingerprint
}

func (e helpKeyExpiredDeleted) ID() string { return "help_key_expired_deleted" }
func (e helpKeyExpiredDeleted) RenderInto(eml *email) (err error) {
	eml.subject = helpKeyExpiredDeletedSubject
	eml.htmlBody, err = render(helpKeyExpiredDeletedBodyTemplate, e)
	return err
}

const helpKeyExpiredDeletedSubject = "❌ We're deleting your expired PGP key"
const helpKeyExpiredDeletedBodyTemplate = `The public key you uploaded to Fluidkeys has expired. To protect your personal information and ensure we're only hosting valid keys, we're about to delete the key from our server.

Email: {{.Email}}
Key: {{.Fingerprint}}

This includes your email address so you won't receive any more automated emails like this one.


## Receiving secrets will no longer work

When someone sends you a secret, the fk application uses our server to search for your key based on your email address. This will no longer work.


## Carry on using Fluidkeys: extend and upload your key

If you want to carry on using Fluidkeys, you can extend and upload your public key by running:

fk key maintain
fk key upload

Once you've verified your email again, everything will work as before.


## What happened?

We'd love to know why you stopped using Fluidkeys, and we're very happy to help! Hit reply and let us know your thoughts.

Thanks,

Paul & Ian`
