package verification

import (
	"crypto/ecdsa"
	"errors"

	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
)

type AuthenticationStage struct{}

// Verify payloads for the authentication stage
//
// Rules:
// - there must only be two envelopes
// - first envelope:
// 		type: must be granted.dev/Init/v0.1
//		signatures: user and identity server
//		payload: public key and user ID must match user
// - second envelope:
// 		type: must be granted.dev/Authenticated/v0.1
//		signatures: identity server
//		payload:
func (s *AuthenticationStage) Verify(f schema.Facts, b schema.Bundle) error {
	if len(b) != 2 {
		return errors.New("bundle did not contain 2 envelopes")
	}

	err := VerifyEnvelope(f, b[0], types.PayloadInit, []ecdsa.PublicKey{f.Actors.User.PublicKey, f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	err = VerifyEnvelope(f, b[1], types.PayloadAuthenticated, []ecdsa.PublicKey{f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	return nil
}
