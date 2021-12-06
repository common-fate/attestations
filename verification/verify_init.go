package verification

import (
	"crypto/ecdsa"
	"errors"

	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
)

type InitStage struct{}

// Verify payloads for the authentication stage
//
// Rules:
// - there must only be one envelope
// - first envelope:
// 		type: must be granted.dev/Init/v0.1
//		signatures: user and identity server
//		payload: public key must match user
func (s *InitStage) Verify(f schema.Facts, b schema.Bundle) error {
	if len(b) != 1 {
		return errors.New("bundle did not contain 1 envelopes")
	}

	err := VerifyEnvelope(f, b[0], types.PayloadInit, []ecdsa.PublicKey{f.Actors.User.PublicKey})
	if err != nil {
		return err
	}

	return nil
}
