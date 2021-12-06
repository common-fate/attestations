package verification

import (
	"crypto/ecdsa"
	"errors"

	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
)

type AutoApproveDecisionVerifier struct{}

// Verify payloads for the access request stage
//
// Rules:
// - there must only be 3 envelopes
// - first envelope:
// 		type: must be granted.dev/Init/v0.1
//		signatures: user and identity server
//		payload: public key and user ID must match user
// - second envelope:
// 		type: must be granted.dev/Authenticated/v0.1
//		signatures: identity server
//		payload: user ID must match user
// - third envelope:
// 		type: must be granted.dev/AccessRequest/v0.1
//		signatures: user and identity server
//		payload:
// - fourth envelope:
// 		type: must be granted.dev/Decision/v0.1
//		signatures: identity server
//		payload:
// - fifth envelope:
// 		type: must be granted.dev/GrantCreated/v0.1
//		signatures: identity server
//		payload:
func (s *AutoApproveDecisionVerifier) Verify(f schema.Facts, b schema.Bundle) error {
	if len(b) != 5 {
		return errors.New("bundle did not contain 4 envelopes")
	}

	err := VerifyEnvelope(f, b[0], types.PayloadInit, []ecdsa.PublicKey{f.Actors.User.PublicKey, f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	err = VerifyEnvelope(f, b[1], types.PayloadAuthenticated, []ecdsa.PublicKey{f.Actors.User.PublicKey, f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	err = VerifyEnvelope(f, b[2], types.PayloadAccessRequest, []ecdsa.PublicKey{f.Actors.User.PublicKey, f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	err = VerifyEnvelope(f, b[3], types.PayloadDecision, []ecdsa.PublicKey{f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	err = VerifyEnvelope(f, b[4], types.PayloadGrantCreated, []ecdsa.PublicKey{f.Actors.IdentityServer.PublicKey})
	if err != nil {
		return err
	}

	return nil
}
