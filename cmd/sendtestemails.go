package cmd

import (
	"fmt"
	"os"

	"github.com/fluidkeys/api/email"
)

// SendTestEmails sends test emails to the given email address.
func SendTestEmails() (exitCode int) {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: send_test_emails <to_email>\n")
		return 1
	}

	to := os.Args[2]
	fmt.Printf("Sending test emails to %s\n", to)

	if err := email.SendTestEmails(to); err != nil {
		fmt.Printf("error sending test emails: %v\n", err)
		return 1
	}
	return 0
}
