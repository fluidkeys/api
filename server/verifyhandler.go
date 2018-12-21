package server

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/fluidkeys/api/datastore"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

// verifyEmailHandler is the URL someone clicks in their email to verify the link from an email
// to a key.
// It handles GET and POST:
// * GET returns an HTML page with a simple form / verify link
// * POST actually verifies the email
// This is because GET should never modify a resource. In practice links in emails do get visited
// by things like antivirus scanners, link previewers etc, so it's important to follow this.
func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	verifyUUID, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		writeJsonError(w, fmt.Errorf("error parsing UUID: %v", err), http.StatusBadRequest)
		return
	}

	switch r.Method {

	case "GET":
		w.Write([]byte(verifyPage))

	case "POST":
		err = verifyEmailByUUID(verifyUUID, userAgent(r), ipAddress(r))

		if err != nil {
			http.Error(w,
				err.Error(),
				http.StatusBadRequest)

		} else {
			w.Write([]byte(successPage))
		}
	}
}

// verifyEmailByUUID takes a uuid from an email verification link and does the following:
// * verifies that there's an active email_verification for the UUID
// * looks up the email address and key id
// * verifies there no existing email_key_link for the email address
// * creates an email_key_link
// * updates the email_verification's verify_user_agent, verify_ip_address
func verifyEmailByUUID(secretUUID uuid.UUID, userAgent string, ipAddress string) error {
	return datastore.RunInTransaction(func(txn *sql.Tx) error {
		email, fingerprint, err := datastore.GetVerification(txn, secretUUID)
		if err != nil {
			return fmt.Errorf("error getting verification: %v", err)
		}

		_, alreadyLinked, err := datastore.GetArmoredPublicKeyForEmail(txn, email)
		if err != nil {
			return err
		} else if alreadyLinked {
			return fmt.Errorf("email is already linked to a key")
		}

		err = datastore.LinkEmailToFingerprint(txn, email, *fingerprint)
		if err != nil {
			return fmt.Errorf("Error linking email to key: %v", err)
		}

		err = datastore.MarkVerificationAsVerified(txn, secretUUID, userAgent, ipAddress)
		if err != nil {
			return fmt.Errorf("error updating verification: %v", err)
		}

		return nil // success: allow transaction to commit
	})
}

const verifyPage string = `<html>
	<body>
		<h1>Verifying email...</h1>
		<p><a href="#">If the page doesn't reload automatically...</a></p>
		<form method="post" action="#">
		  <input type="submit" value="Verify email address now" />
		</form>

		<script>
		setTimeout(function() {
			document.forms[0].submit();
		}, 0);
		</script>
	</body>
</html>`

const errorPage string = `<html>
	<body>
		<h1>Something went wrong</h1>
		<p>%s</p>
	</body>
</html>`

const successPage string = `<html>
	<body>
		<h1>Email verified</h1>
	</body>
</html>`
