package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func init() {

}

func SendVerificationEmails(publicKey *pgpkey.PgpKey, userAgent, ipAddress string) error {
	log.Printf("userAgent: '%s', ip: '%s'\n", ipAddress, userAgent)
	for _, email := range publicKey.Emails(true) {
		shouldSend, err := shouldSendVerificationEmail(email)
		if err != nil {
			return err
		}

		if !shouldSend {
			continue // skip this email
		}

		emailData := verificationEmail{
			Email:            email,
			VerificationUrl:  "https://example.com/todo",
			RequestIpAddress: ipAddress,
			RequestTime:      time.Now(), // TODO
			KeyFingerprint:   publicKey.Fingerprint().Hex(),
			KeyCreatedDate:   time.Now(), // TODO
		}

		err = sendVerificationEmail(emailData)
		if err != nil {
			return fmt.Errorf("failed to send verification email: %v", err)
		}
	}

	return nil
}

func shouldSendVerificationEmail(email string) (bool, error) {
	_, alreadyLinked, err := datastore.GetArmoredPublicKeyForEmail(email)
	if err != nil {
		return false, err
	}
	if alreadyLinked {
		// 1. it's linked to the same key, in which case there's
		//    nothing to do
		// 2. it's linked to one key, and this is a request
		//    to link the email to a *different* key, which we don't
		//    currently allow. The email_key_link must be deleted
		//    before the email can be linked again. Note that this
		//    happens if the whole linked *key* is deleted.
		return false, nil
	}

	hasActiveVerification, err := datastore.HasActiveVerificationForEmail(email)
	if err != nil {
		return false, err
	}
	if hasActiveVerification {
		// prevents an attacker from mailbombing an email address by
		// creating lots of different keys with the email: if there's
		// an active email verification, it has to expire before
		// another one can be created
		log.Printf("email verification already exists for %s, not sending another", email)
		return false, nil
	}

	return true, nil
}

// emailAlreadyLinkedToAnyKey returns true if the given email address is
// already associated with a public key.
// func emailAlreadyLinkedToAnyKey(email string) (bool, error) {
// 	_, foundKey, err := datastore.GetArmoredPublicKeyForEmail(email)
//
// 	return foundKey, err
// }
//
// // emailHasActiveVerification returns true if there's already an active
// // (not-expired) verification. A verification would exist if we've recently
// // sent created one and sent them an email.
// func emailHasActiveVerification(email string) (bool, error) {
// 	hasActiveVerification, err := datastore.HasActiveVerificationForEmail(email)
//
// 	return hasActiveVerification, err
// }

func sendVerificationEmail(emailData verificationEmail) error {

	e := email{
		subject:  renderEmailSubject("verify", emailData),
		htmlBody: renderEmailHtmlBody("verify", emailData),
	}

	log.Printf("sending email verification to '%s'", emailData.Email)
	return sendEmail(e)
}

func renderEmailSubject(templateName string, emailData interface{}) string {
	return "[email subject]"
}

func renderEmailHtmlBody(templateName string, emailData interface{}) string {
	t := template.Must(template.New(templateName + ".html").ParseFiles(templateName + ".html"))
	buf := bytes.NewBuffer(nil)
	t.Execute(buf, emailData)
	return buf.String()
}

func sendEmail(e email) error {
	// See https://medium.com/@dhanushgopinath/sending-html-emails-using-templates-in-golang-9e953ca32f3d
	// See https://github.com/zemirco/email/blob/master/email.go

	msg := "Subject: " + e.subject + "\n"
	msg += "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n"
	msg += "\n\n"
	msg += e.htmlBody

	fmt.Print(e.htmlBody)
	return fmt.Errorf("not implemented")
}

type email struct {
	to       string
	replyTo  string
	bcc      string
	subject  string
	htmlBody string
}

type verificationEmail struct {
	Email            string
	VerificationUrl  string
	RequestIpAddress string
	RequestTime      time.Time
	KeyFingerprint   string
	KeyCreatedDate   time.Time
}
