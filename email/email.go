package email

import (
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
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

	log.Printf("email.htmlBody: %s\n", email.htmlBody)

	if err := email.send(); err != nil {
		return fmt.Errorf("error sending mail: %v", err)
	}
	return nil
}

// shouldSendVerificationEmail returns true if an email address should receive a new verification
// email
func shouldSendVerificationEmail(txn *sql.Tx, email string) (bool, error) {
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
	return fmt.Sprintf("https://api.fluidkeys.com/v1/emails/verify/%s", secretUUID.String())
}

type email struct {
	to       string
	from     string
	replyTo  string
	bcc      string
	subject  string
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
		e.subject, err = render(verifySubjectTemplate, data)
		if err != nil {
			return err
		}

		e.htmlBody, err = render(verifyHtmlBodyTemplate, data)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown template: %s", templateName)
	}

	return nil
}

func (e *email) send() error {

	if e.htmlBody == "" {
		return fmt.Errorf("empty HTML body")
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
	header.Set(textproto.CanonicalMIMEHeaderKey("content-type"), "text/html; charset=UTF-8")
	header.Set(textproto.CanonicalMIMEHeaderKey("mime-version"), "1.0")
	header.Set(textproto.CanonicalMIMEHeaderKey("subject"), e.subject)

	var buffer bytes.Buffer

	// write header
	for key, value := range header {
		buffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value[0]))
	}

	// write body
	buffer.WriteString(fmt.Sprintf("\r\n%s", e.htmlBody))

	if disableSendEmail {
		fmt.Printf("DISABLE_SEND_EMAIL=1, email:\n----\n%s\n----\n", buffer.String())
		return nil
	} else {
		addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
		auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
		return smtp.SendMail(addr, auth, from.Address, []string{to.Address}, buffer.Bytes())
	}
}

func render(templateText string, emailTemplateData interface{}) (string, error) {

	t, err := template.New("").Funcs(funcMap).Parse(templateText)

	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	err = t.Execute(buf, emailTemplateData)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
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

// funcMap defines template functions that transform variables into strings in the template
var funcMap = template.FuncMap{
	"FormatDateTime": func(t time.Time) string {
		return t.Format("15:04:05 MST on 2 January 2006")
	},
	"FormatDate": func(t time.Time) string {
		return t.Format("2 January 2006")
	},
}

const verifySubjectTemplate = "Verify {{.Email}} on Fluidkeys"
const verifyHtmlBodyTemplate string = `Verify your email address to allow others to find your PGP key and send you encrypted secrets.

Click this link to verify your key now:

<a href="{{.VerificationUrl}}">Verify {{.Email}} and allow others to find your PGP key</a>

---

You're receiving this email because a PGP public key was uploaded to Fluidkeys from {{.RequestIpAddress}} at {{.RequestTime|FormatDateTime}}.

Key {{.KeyFingerprint}} created {{.KeyCreatedDate|FormatDate}}

If you aren't expecting this email, please reply to this email so we can investigate.`
