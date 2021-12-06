package schema

import (
	"encoding/json"

	"github.com/common-fate/attestations/types"
)

type Decision struct {
	AutoAllow       bool
	RequireApproval bool
}

type DecisionPayload struct {
	Decision    Decision      `json:"decision"`
	PayloadType types.Payload `json:"type"`
}

func NewDecisionPayload(d Decision) *DecisionPayload {
	return &DecisionPayload{
		Decision:    d,
		PayloadType: types.PayloadDecision,
	}
}

func (m *DecisionPayload) Type() types.Payload {
	return m.PayloadType
}

func (m *DecisionPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(*m)
}

func (m *DecisionPayload) ValidateContents(f Facts) error {
	return nil
}
