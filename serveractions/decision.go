package serveractions

import (
	"context"

	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
)

func (a *ServerActor) Decision(ctx context.Context, b schema.Bundle, d schema.Decision) (schema.Bundle, error) {
	// the signature bundle should be as follows
	// 1 - INIT
	// 2 - AUTHENTICATED
	// 3 - ACCESS_REQUEST

	requestEnv := b[2]
	// double check that we're signing an access request payload
	_, err := schema.DeserializePayload(requestEnv.Payload, types.PayloadAccessRequest)
	if err != nil {
		return nil, err
	}

	err = requestEnv.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}

	decisionPayload := schema.NewDecisionPayload(d)
	decisionEnv, err := schema.EnvelopeFromPayload(decisionPayload)
	if err != nil {
		return nil, err
	}

	err = decisionEnv.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}

	bundle := schema.Bundle{
		b[0],
		b[1],
		requestEnv,
		decisionEnv,
	}

	return bundle, nil
}
