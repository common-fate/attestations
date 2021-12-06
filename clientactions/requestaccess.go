package clientactions

import (
	"context"

	"github.com/common-fate/attestations/schema"
)

func (a *ClientActor) RequestAccess(ctx context.Context, bundle schema.Bundle, req schema.AccessRequest) (schema.Bundle, error) {
	authMsg := schema.NewAccessRequestMessage(req)
	accessEnvelope, err := schema.EnvelopeFromPayload(authMsg)
	if err != nil {
		return nil, err
	}
	err = accessEnvelope.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}
	b := append(bundle, accessEnvelope)
	return b, nil
}
