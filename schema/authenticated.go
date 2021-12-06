package schema

import (
	"encoding/json"
	"time"

	"github.com/common-fate/attestations/types"
)

type AuthenticatedPayload struct {
	Time        int64                  `json:"time"`
	UserID      string                 `json:"userId"`
	Claims      map[string]interface{} `json:"claims"`
	PayloadType types.Payload          `json:"type"`
}

type AuthMessageOpts struct {
	Time   time.Time
	UserID string
	Claims map[string]interface{}
}

func NewAuthenticatedMessage(opts AuthMessageOpts) *AuthenticatedPayload {
	return &AuthenticatedPayload{
		Time:        opts.Time.UnixNano(),
		UserID:      opts.UserID,
		Claims:      opts.Claims,
		PayloadType: types.PayloadAuthenticated,
	}
}

func (m *AuthenticatedPayload) Type() types.Payload {
	return m.PayloadType
}

func (m *AuthenticatedPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(*m)
}

func (m *AuthenticatedPayload) ValidateContents(f Facts) error {
	if m.UserID != string(f.Actors.User.ID) {
		return &ErrInvalidPayloadContents{
			Msg: "user ID didn't match",
		}
	}

	return nil
}
