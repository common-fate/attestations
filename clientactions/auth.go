package clientactions

import (
	"context"

	"github.com/common-fate/attestations/schema"
)

// CounterSignAuth adds the user's own signature to the AUTH bundle received from the server
func (a *ClientActor) CounterSignAuth(ctx context.Context, b schema.Bundle) (schema.Bundle, error) {
	init := b[0]
	auth := b[1]

	err := auth.Sign(ctx, a.signer)
	if err != nil {
		return nil, err
	}

	newBundle := schema.Bundle{init, auth}
	return newBundle, nil
}
