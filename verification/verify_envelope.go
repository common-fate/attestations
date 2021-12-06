package verification

import (
	"crypto/ecdsa"

	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
)

var AccessRequestBundle = []types.Payload{types.PayloadInit, types.PayloadAuthenticated, types.PayloadAccessRequest}

func VerifyEnvelope(f schema.Facts, e schema.Envelope, expectedType types.Payload, signedBy []ecdsa.PublicKey) error {
	payload, err := schema.DeserializePayload(e.Payload, expectedType)
	if err != nil {
		return err
	}

	// validate signatures
	err = e.VerifySignatures(signedBy)
	if err != nil {
		return err
	}

	// validate payload contents
	return payload.ValidateContents(f)
}

// ParseBundleNoVerification verifies that a bundle contains an expected set of payloads,
// but doesn't verify signatures or contents.
// Used by the metadata server to perform an initial check that the bundle is the right type.
func ParseBundleNoVerification(b schema.BundleInput, expected []types.Payload) (schema.Bundle, error) {
	for i, t := range expected {
		_, err := schema.DeserializePayload(b[i].Payload, t)
		if err != nil {
			return nil, err
		}
	}
	return schema.Bundle(b), nil
}
