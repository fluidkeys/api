package email

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestRenderVerifyEmail(t *testing.T) {
	now := time.Date(2018, 6, 15, 16, 15, 37, 0, time.UTC)
	createdAt := time.Date(2016, 2, 5, 0, 0, 0, 0, time.UTC)
	fp := fingerprint.MustParse("A999B7498D1A8DC473E53C92309F635DAD1B5517")

	data := verifyEmail{
		Email:            "test@example.com",
		VerificationUrl:  "https://example.com/test",
		RequestIpAddress: "1.1.1.1",
		RequestTime:      now,
		KeyFingerprint:   fp.Hex(),
		KeyCreatedDate:   createdAt,
	}

	t.Run("test subject", func(t *testing.T) {
		gotSubject, err := render(verifySubjectTemplate, data)
		assert.ErrorIsNil(t, err)

		expectedSubject := `Verify test@example.com on Fluidkeys`
		assert.Equal(t, expectedSubject, gotSubject)
	})

	t.Run("test html body", func(t *testing.T) {
		gotHtml, err := render(verifyHtmlBodyTemplate, data)
		assert.ErrorIsNil(t, err)

		assertEqualMultiLineStrings(t, expectedHtml, gotHtml)
	})

}

func assertEqualMultiLineStrings(t *testing.T, expected string, got string) {
	if expected == got {
		return
	}

	expectedLines := strings.Split(expected, "\n")
	gotLines := strings.Split(got, "\n")

	var i int

	for i < len(expectedLines) && i < len(gotLines) {
		if expectedLines[i] != gotLines[i] {
			fmt.Printf("< %s\n", expectedLines[i])
			fmt.Printf("> %s\n", gotLines[i])
		}

		i += 1
	}
	// TODO: print out any extra lines present in 1 and not the other

	t.Fatalf("strings differ: expected %d lines, got %d lines^^",
		len(expectedLines), len(gotLines))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const expectedHtml string = `Verify your email address to allow others to find your PGP key and send you encrypted secrets.

Click this link to verify your key now:

<a href="https://example.com/test">Verify test@example.com and allow others to find your PGP key</a>

---

You're receiving this email because a PGP public key was uploaded to Fluidkeys from 1.1.1.1 at 16:15:37 UTC on 15 June 2018.

Key A999B7498D1A8DC473E53C92309F635DAD1B5517 created 5 February 2016

If you aren't expecting this email, please reply to this email so we can investigate.`
