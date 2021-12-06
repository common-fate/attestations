package clientactions

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/common-fate/attestations/schema"
)

func (a *ClientActor) Init(ctx context.Context, publicKey ecdsa.PublicKey) (schema.Bundle, error) {
	publicDerBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	msg := schema.NewInitMessage(publicDerBytes)
	env, err := schema.EnvelopeFromPayload(msg)
	if err != nil {
		return nil, err
	}
	err = env.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}

	b := schema.Bundle{
		env,
	}
	return b, nil
}
