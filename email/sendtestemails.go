package email

import "fmt"

// SendTestEmails sends a plaintext and an HTML email to the given to address.
func SendTestEmails(to string) error {
	templates := []emailTemplateInterface{
		testEmailText{},
		testEmailHTML{},
	}

	const (
		from    = "Fluidkeys <help@mail.fluidkeys.com>"
		replyTo = "Fluidkeys <help@fluidkeys.com>"
	)

	for _, template := range templates {
		email := email{
			to:      to,
			from:    from,
			replyTo: replyTo,
		}

		err := template.RenderInto(&email)
		if err != nil {
			return fmt.Errorf("error rendering email: %v", err)
		}

		if err := email.send(); err != nil {
			return fmt.Errorf("error sending mail: %v", err)
		}
	}
	return nil
}

type testEmailText struct{}

func (e testEmailText) ID() string { return "test_email_text" }
func (e testEmailText) RenderInto(eml *email) (err error) {
	eml.subject = "Test email (text)"
	eml.textBody, err = renderText(testEmailTextBodyTemplate, e)
	return err
}

const testEmailTextBodyTemplate = `This is a test email in text format (not HTML)

This should be on a new line.`

type testEmailHTML struct{}

func (e testEmailHTML) ID() string { return "test_email_html" }
func (e testEmailHTML) RenderInto(eml *email) (err error) {
	eml.subject = "Test email (HTML)"
	eml.htmlBody, err = renderHTML(testEmailHTMLBodyTemplate, e)
	return err
}

const testEmailHTMLBodyTemplate = `<h1>This is a test email in HTML format</h1>

<p>This should be on a new line.</p>

<b>This should be <b>bold</b></p>
`
