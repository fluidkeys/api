package server

import (
	"bytes"
	"fmt"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/clearsign"

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

func verify(clearsignedData []byte, publicKey *pgpkey.PgpKey) (verifiedPlaintext []byte, err error) {
	block, _ := clearsign.Decode([]byte(clearsignedData))
	if block == nil {
		return nil, fmt.Errorf("error finding clearsigned data")
	}

	var keyring openpgp.EntityList = []*openpgp.Entity{&publicKey.Entity}

	signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body)
	if err != nil {
		return nil, fmt.Errorf("signature error: %v", err)
	} else if signer.PrimaryKey.Fingerprint != publicKey.Entity.PrimaryKey.Fingerprint {
		return nil, fmt.Errorf("signed by wrong key")
	}

	return block.Plaintext, nil
}
