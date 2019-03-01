package server

import "fmt"

var errSignedByWrongKey = fmt.Errorf("signed by wrong key")

// errBadSignature means the signed data may have been tampered with
var errBadSignature = fmt.Errorf("bad signature")
