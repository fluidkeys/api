package email

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"time"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

func init() {
	if os.Getenv("DISABLE_SEND_EMAIL") == "1" {
		disableSendEmail = true
		return
	}

	var got = false
	smtpHost, got = os.LookupEnv("SMTP_HOST")
	if !got {
		log.Panic("SMTP_HOST not set (set DISABLE_SEND_EMAIL=1 to disable)")
	}

	smtpPort, got = os.LookupEnv("SMTP_PORT")
	if !got {
		log.Panic("SMTP_PORT not set (set DISABLE_SEND_EMAIL=1 to disable)")
	}

	port, err := strconv.Atoi(smtpPort)
	if err != nil || port < 0 || port > 65535 {
		log.Panicf("invalid SMTP_PORT '%d', should be an integer in range 1-65535", port)
	}

	smtpUsername, got = os.LookupEnv("SMTP_USERNAME")
	if !got {
		log.Panic("SMTP_USERNAME not set (set DISABLE_SEND_EMAIL=1 to disable)")
	}

	smtpPassword, got = os.LookupEnv("SMTP_PASSWORD")
	if !got {
		log.Panic("SMTP_PASSWORD not set (set DISABLE_SEND_EMAIL=1 to disable)")
	}
}

// emailTemplateInterface is used to define a specific type of email.
type emailTemplateInterface interface {
	// ID must return a unique string for this type of email. This is stored in the database
	// to ensure we don't send the same type of email multiple times.
	// Example: `help_key_expires_3_days`
	ID() string

	// RenderInto should populate the subject and htmlBody fields in the given email struct, or
	// return an error if that fails.
	RenderInto(eml *email) error
}

type VerificationMetadata struct {
	RequestUserAgent string
	RequestIpAddress string
	RequestTime      time.Time
}

// SendVerificationEmails iterates through the email addresses on the given key and works out
// whether to send each one a verification email.
// If so, it renders and sends the verification email, and records a new verification in the
// database.
func SendVerificationEmails(
	txn *sql.Tx, publicKey *pgpkey.PgpKey, meta VerificationMetadata) error {

	for _, email := range publicKey.Emails(true) {
		shouldSend, err := shouldSendVerificationEmail(txn, email)
		if err != nil {
			return err
		} else if shouldSend {
			if err := sendVerificationEmail(txn, email, publicKey, meta); err != nil {
				return err
			}
		}
	}
	return nil
}

func sendVerificationEmail(
	txn *sql.Tx, emailAddress string, publicKey *pgpkey.PgpKey,
	meta VerificationMetadata) error {

	verifySecretUUID, err := datastore.CreateVerification(
		txn, emailAddress, publicKey.Fingerprint(),
		meta.RequestUserAgent,
		meta.RequestIpAddress,
		meta.RequestTime,
	)
	if err != nil {
		return err
	}

	emailTemplateData := verifyEmail{
		Email:            emailAddress,
		VerificationUrl:  makeVerificationUrl(*verifySecretUUID),
		RequestIpAddress: meta.RequestIpAddress,
		RequestTime:      meta.RequestTime,
		KeyFingerprint:   publicKey.Fingerprint().Hex(),
		KeyCreatedDate:   publicKey.PrimaryKey.CreationTime,
	}

	email := email{
		to:      emailAddress,
		from:    "Fluidkeys <verify@mail.fluidkeys.com>",
		replyTo: "Fluidkeys Security <security@fluidkeys.com>",
		bcc:     "hello@fluidkeys.com",
	}

	if err := email.renderSubjectAndBody(emailTemplateData); err != nil {
		return fmt.Errorf("error rendering email: %v", err)
	}

	if err := email.send(); err != nil {
		return fmt.Errorf("error sending mail: %v", err)
	}
	log.Printf("sending verification email to %s for key %s",
		emailAddress, publicKey.Fingerprint().Hex())

	log.Printf("local verification link: %s", makeDevVerificationUrl(*verifySecretUUID))
	return nil
}

// shouldSendVerificationEmail returns true if an email address should receive a new verification
// email
func shouldSendVerificationEmail(txn *sql.Tx, email string) (bool, error) {
	_, alreadyLinked, err := datastore.GetArmoredPublicKeyForEmail(txn, email)
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
		log.Printf("email '%s' already linked to a key, not sending email", email)
		return false, nil
	}

	hasActiveVerification, err := datastore.HasActiveVerificationForEmail(txn, email)
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

	log.Printf("no currently-active verifications for email '%s'", email)

	return true, nil
}

func makeVerificationUrl(secretUUID uuid.UUID) string {
	return fmt.Sprintf("https://api.fluidkeys.com/v1/email/verify/%s", secretUUID.String())
}

func makeDevVerificationUrl(secretUUID uuid.UUID) string {
	return fmt.Sprintf("http://localhost:4747/v1/email/verify/%s", secretUUID.String())
}

func sendEmail(
	userProfileUUID uuid.UUID,
	template emailTemplateInterface,
	to string,
	from string,
	replyTo string,
	rateLimit *time.Duration) error {

	allowed, err := datastore.CanSendWithRateLimit(
		template.ID(), userProfileUUID, rateLimit, time.Now(),
	)
	if err != nil {
		return err
	} else if !allowed {
		return errRateLimit
	}

	email := email{
		to:      to,
		from:    from,
		replyTo: replyTo,
	}

	err = template.RenderInto(&email)
	if err != nil {
		return fmt.Errorf("error rendering email: %v", err)
	}

	err = datastore.RunInTransaction(func(txn *sql.Tx) error {
		now := time.Now()
		if err := datastore.RecordSentEmail(txn, template.ID(), userProfileUUID, now); err != nil {
			log.Printf("error in RecordSentEmail")
			return err
		}

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

type email struct {
	to       string
	from     string
	replyTo  string
	bcc      string
	subject  string
	textBody string
	htmlBody string
}

func inferTemplateName(emailTemplateData interface{}) (string, error) {
	switch emailTemplateData.(type) {
	case verifyEmail:
		return "verify", nil
	}

	return "", fmt.Errorf("failed to get template name from data: %v", emailTemplateData)
}

func (e *email) renderSubjectAndBody(data interface{}) (err error) {
	templateName, err := inferTemplateName(data)
	if err != nil {
		return err
	}

	switch templateName {
	case "verify":
		e.subject, err = renderText(verifySubjectTemplate, data)
		if err != nil {
			return err
		}

		e.htmlBody, err = renderHTML(verifyHtmlBodyTemplate, data)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown template: %s", templateName)
	}

	return nil
}

func (e *email) send() error {

	if e.htmlBody == "" && e.textBody == "" {
		return fmt.Errorf("empty htmlBody and textBody")
	}

	if e.subject == "" {
		return fmt.Errorf("empty subject")
	}

	from, err := mail.ParseAddress(e.from) // validate from address
	if err != nil {
		return fmt.Errorf("error parsing address: %v", err)
	}

	to, err := mail.ParseAddress(e.to) // validate to address
	if err != nil {
		return fmt.Errorf("error parsing to address: %v", err)
	}

	header := textproto.MIMEHeader{}
	header.Set(textproto.CanonicalMIMEHeaderKey("from"), e.from)
	header.Set(textproto.CanonicalMIMEHeaderKey("to"), e.to)
	header.Set(textproto.CanonicalMIMEHeaderKey("reply-to"), e.replyTo)
	if e.htmlBody != "" {
		header.Set(textproto.CanonicalMIMEHeaderKey("content-type"), "text/html; charset=UTF-8")
	} else {
		header.Set(textproto.CanonicalMIMEHeaderKey("content-type"), "text/plain; charset=UTF-8")
	}
	header.Set(textproto.CanonicalMIMEHeaderKey("mime-version"), "1.0")
	header.Set(textproto.CanonicalMIMEHeaderKey("subject"), e.subject)

	var buffer bytes.Buffer

	// write header
	for key, value := range header {
		buffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value[0]))
	}

	if e.htmlBody != "" {
		buffer.WriteString(fmt.Sprintf("\r\n%s", e.htmlBody))
	} else {
		buffer.WriteString(fmt.Sprintf("\r\n%s", e.textBody))
	}

	if disableSendEmail {
		fmt.Printf("DISABLE_SEND_EMAIL=1, email:\n----\n%s\n----\n", buffer.String())
		return nil
	} else {
		addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
		auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
		log.Printf("sending email to %s via %s", to.Address, addr)
		return smtp.SendMail(addr, auth, from.Address, []string{to.Address}, buffer.Bytes())
	}
}

var (
	disableSendEmail bool
	smtpHost         string
	smtpPort         string
	smtpUsername     string
	smtpPassword     string
)

// verifyEmail holds the data required to populate the "verify" email templates
type verifyEmail struct {
	Email            string
	VerificationUrl  string
	RequestIpAddress string
	RequestTime      time.Time
	KeyFingerprint   string
	KeyCreatedDate   time.Time
}

var errRateLimit = fmt.Errorf("rate limit: not sending same email so soon")

const verifySubjectTemplate = "Verify {{.Email}} on Fluidkeys"
const verifyHtmlBodyTemplate string = `<!DOCTYPE HTML>

<html>
<body>
<p>
Verify your email address to allow others to find your PGP key and send you encrypted secrets.
</p>

<p>
<a href="{{.VerificationUrl}}">Verify {{.Email}}</a>
</p>

<p>
If clicking the link above doesn't work, copy and paste this link into your browser:
</p>

<p>
<a href="{{.VerificationUrl}}">{{.VerificationUrl}}</a>
</p>

<hr>
<p>
You're receiving this email because a PGP public key was uploaded to <a href="https://www.fluidkeys.com">Fluidkeys</a> from {{.RequestIpAddress}} at {{.RequestTime|FormatDateTime}}.

<p>
Key {{.KeyFingerprint}} created {{.KeyCreatedDate|FormatDate}}
</p>

<p>
If you aren't expecting this email, please reply to this email so we can investigate.
</p>

</body>
</html>`
