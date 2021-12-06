package schema

import (
	"errors"

	"github.com/common-fate/attestations/types"
)

// LoadUserFromBundle retrieves a user ID from an AUTHENTICATED envelope within a
// signature bundle.
func LoadUserFromBundle(b Bundle) (string, error) {
	for _, e := range b {
		p, _ := DeserializePayload(e.Payload, types.PayloadAuthenticated)
		authPayload, ok := p.(*AuthenticatedPayload)
		if ok {
			return authPayload.UserID, nil
		}
	}

	return "", errors.New("AUTHENTICATED envelope not found in bundle")
}
