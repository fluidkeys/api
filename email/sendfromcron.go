package email

import "log"

// SendFromCron is periodically called from cron, figures out which it needs to
// send, sends them, and records they've been sent in the datastore.
func SendFromCron() (sawError error) {
	if err := SendKeyExpiresEmails(); err != nil {
		log.Printf("error calling SendKeyExpiresEmails: %v", err)
		sawError = err
	}

	return sawError
}
