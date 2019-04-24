package email
import "fmt"

// SendFromCron is periodically called from cron, figures out which it needs to
// send, sends them, and records they've been sent in the datastore.
func SendFromCron() error {
	return fmt.Errorf("not implemented")
}
