package cmd

import (
	"fmt"

	"github.com/fluidkeys/api/email"
)

func SendEmails() (exitCode int) {
	if err := email.SendFromCron(); err != nil {
		fmt.Printf("error sending emails: %v\n", err)
		return 1
	}
	return 0
}
