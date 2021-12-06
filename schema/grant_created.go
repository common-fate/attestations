package schema

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/common-fate/attestations/types"
)

type Grant struct {
	Type       string
	ExpiresAt  time.Time
	AWSRoleARN string
}

type GrantCreatedPayload struct {
	Grant       Grant         `json:"decision"`
	PayloadType types.Payload `json:"type"`
}

func NewGrantCreatedPayload(g Grant) *GrantCreatedPayload {
	return &GrantCreatedPayload{
		Grant:       g,
		PayloadType: types.PayloadGrantCreated,
	}
}

func (m *GrantCreatedPayload) Type() types.Payload {
	return m.PayloadType
}

func (m *GrantCreatedPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(*m)
}

func (m *GrantCreatedPayload) ValidateContents(f Facts) error {
	if f.Time.After(m.Grant.ExpiresAt) {
		return errors.New("grant is expired")
	}

	return nil
}
