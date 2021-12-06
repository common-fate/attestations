package serveractions

import (
	"context"

	"github.com/common-fate/attestations/schema"
)

func (a *ServerActor) Authenticate(ctx context.Context, initEnv schema.Envelope, opts schema.AuthMessageOpts) (schema.Bundle, error) {
	err := initEnv.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}
	authMsg := schema.NewAuthenticatedMessage(opts)
	authEnvelope, err := schema.EnvelopeFromPayload(authMsg)
	if err != nil {
		return nil, err
	}
	err = authEnvelope.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}
	b := schema.Bundle{
		initEnv,
		authEnvelope,
	}

	return b, nil
}
