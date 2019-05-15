package server

import "fmt"

var errAuthKeyNotFound = fmt.Errorf("invalid authorization")

var errIdenticalRequestAlreadyExists = fmt.Errorf(
	"request to join team already exists with the same email and fingerprint")

var errConflictingRequestAlreadyExists = fmt.Errorf(
	"request to join team already exists for that email with a different fingerprint")

var errSignedByWrongKey = fmt.Errorf("signed by wrong key")

// errBadSignature means the signed data may have been tampered with
var errBadSignature = fmt.Errorf("bad signature")

var errNotAnAdminInExistingTeam = fmt.Errorf("signing key is not an admin of the team")
