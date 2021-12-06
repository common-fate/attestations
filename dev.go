package attestations

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func DevPublicKey(path string) (*ecdsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	//PEM decoding
	block, _ := pem.Decode(bytes)

	//X509 der decoding
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key was wrong type")
	}

	return pubKey, nil
}
