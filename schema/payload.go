package schema

import (
	"encoding/json"
	"fmt"

	"github.com/common-fate/attestations/types"
)

type Payload interface {
	MarshalJSON() ([]byte, error)
	Type() types.Payload
	ValidateContents(f Facts) error
}

type ErrInvalidPayloadType struct {
	Expected types.Payload
	Actual   types.Payload
}

func (e *ErrInvalidPayloadType) Error() string {
	return fmt.Sprintf("payload type %s did not match expected type %s", e.Actual.String(), e.Expected.String())
}

type ErrInvalidPayloadContents struct {
	Msg string
}

func (e *ErrInvalidPayloadContents) Error() string {
	return fmt.Sprintf("invalid payload contents: %s", e.Msg)
}

func DeserializePayload(payload []byte, expected types.Payload) (Payload, error) {
	var pt struct {
		PayloadType types.Payload `json:"type"`
	}

	err := json.Unmarshal(payload, &pt)
	if err != nil {
		return nil, err
	}

	var p Payload

	switch pt.PayloadType {
	case types.PayloadInit:
		var m InitPayload
		err = json.Unmarshal(payload, &m)
		p = &m
	case types.PayloadAuthenticated:
		var m AuthenticatedPayload
		err = json.Unmarshal(payload, &m)
		p = &m
	case types.PayloadAccessRequest:
		var m AccessRequestPayload
		err = json.Unmarshal(payload, &m)
		p = &m
	case types.PayloadDecision:
		var m DecisionPayload
		err = json.Unmarshal(payload, &m)
		p = &m
	case types.PayloadGrantCreated:
		var m GrantCreatedPayload
		err = json.Unmarshal(payload, &m)
		p = &m
	default:
		return nil, fmt.Errorf("unhandled payload type %s", pt.PayloadType)
	}
	if err != nil {
		return nil, err
	}

	if p.Type() != expected {
		return nil, &ErrInvalidPayloadType{
			Expected: expected,
			Actual:   p.Type(),
		}
	}

	return p, nil
}
