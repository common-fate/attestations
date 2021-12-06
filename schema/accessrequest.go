package schema

import (
	"encoding/json"

	"github.com/common-fate/attestations/types"
)

type AccessRequestPayload struct {
	Request     AccessRequest `json:"request"`
	PayloadType types.Payload `json:"type"`
}

type AccessRequest struct {
	Role   string `json:"role"`
	Reason string `json:"reason"`
}

func NewAccessRequestMessage(req AccessRequest) *AccessRequestPayload {
	return &AccessRequestPayload{
		Request:     req,
		PayloadType: types.PayloadAccessRequest,
	}
}

func (m *AccessRequestPayload) Type() types.Payload {
	return m.PayloadType
}

func (m *AccessRequestPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(*m)
}

func (m *AccessRequestPayload) ValidateContents(f Facts) error {
	return nil
}
