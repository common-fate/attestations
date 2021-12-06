package schema

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
)

func SerializeECDSAPublicKey(key ecdsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	return encoded, nil
}
