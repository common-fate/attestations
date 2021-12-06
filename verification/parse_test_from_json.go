package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/common-fate/attestations/schema"
)

type TestEnvelope struct {
	Payload  schema.Payload
	SignedBy []string
}

type KeyPair struct {
	Public  ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

type KeyPairMap map[string]KeyPair

// MakeTestKeyPairs provides a convenient method to set up named keypairs for testing
func MakeTestKeyPairs(signers []string) (KeyPairMap, error) {
	sigMap := make(KeyPairMap)
	for _, signer := range signers {
		// provision new keys for the signer
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kp := KeyPair{
			Public:  priv.PublicKey,
			Private: priv,
		}
		sigMap[signer] = kp
	}
	return sigMap, nil
}

// ParseTestBundle provides a convenient method to construct bundles with various types of signatures
// for testing
func ParseTestBundle(testBundle []TestEnvelope, sigMap KeyPairMap) (schema.Bundle, error) {
	b := schema.Bundle{}
	ctx := context.Background()

	for _, e := range testBundle {
		env, err := schema.EnvelopeFromPayload(e.Payload)
		if err != nil {
			return nil, err
		}
		for _, signer := range e.SignedBy {
			keys := sigMap[signer]
			err = env.Sign(ctx, &schema.LocalSigner{PrivateKey: keys.Private})
			if err != nil {
				return nil, err
			}
		}
		b = append(b, env)
	}
	return b, nil
}
