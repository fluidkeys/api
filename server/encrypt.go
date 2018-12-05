package server

import (
	"bytes"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"

	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func encryptStringToArmor(secret string, pgpKey *pgpkey.PgpKey) (string, error) {
	buffer := bytes.NewBuffer(nil)
	message, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	pgpWriteCloser, err := openpgp.Encrypt(
		message,
		[]*openpgp.Entity{&pgpKey.Entity},
		nil,
		nil,
		nil,
	)
	if err != nil {
		return "", err
	}
	_, err = pgpWriteCloser.Write([]byte(secret))
	if err != nil {
		return "", err
	}
	pgpWriteCloser.Close()
	message.Close()
	return buffer.String(), nil
}
