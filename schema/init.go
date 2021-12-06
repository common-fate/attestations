package schema

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/common-fate/attestations/types"
)

type InitPayload struct {
	PublicKey   string        `json:"publicKey"`
	PayloadType types.Payload `json:"type"`
}

func NewInitMessage(publicKey []byte) *InitPayload {
	data := base64.StdEncoding.EncodeToString(publicKey)
	return &InitPayload{
		PayloadType: types.PayloadInit,
		PublicKey:   data,
	}
}

func (m *InitPayload) Type() types.Payload {
	return m.PayloadType
}

func (m *InitPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(*m)
}

func (m *InitPayload) ValidateContents(f Facts) error {
	publicDerBytes, err := x509.MarshalPKIXPublicKey(&f.Actors.User.PublicKey)
	if err != nil {
		return err
	}
	encodedPubKey := base64.StdEncoding.EncodeToString(publicDerBytes)

	if m.PublicKey != encodedPubKey {
		return &ErrInvalidPayloadContents{
			Msg: "user public key didn't match",
		}
	}

	return nil
}
