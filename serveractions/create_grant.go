package serveractions

import (
	"context"

	"github.com/common-fate/attestations/schema"
)

func (a *ServerActor) CreateGrant(ctx context.Context, b schema.Bundle, g schema.Grant) (schema.Bundle, error) {
	// the signature bundle should be as follows
	// 1 - INIT
	// 2 - AUTHENTICATED
	// 3 - ACCESS_REQUEST
	// 4 - DECISION
	// ... TODO: handle case where additional APPROVAL envelope may be here
	// 5 - CREATE_GRANT

	payload := schema.NewGrantCreatedPayload(g)
	env, err := schema.EnvelopeFromPayload(payload)
	if err != nil {
		return nil, err
	}

	err = env.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}

	bundle := append(b, env)
	return bundle, nil
}
