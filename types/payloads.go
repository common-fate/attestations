package types

type Payload int

//go:generate go run github.com/alvaroloes/enumer -type=Payload -linecomment -json
const (
	PayloadInit          Payload = iota + 1 // granted.dev/Init/v0.1
	PayloadAuthenticated                    // granted.dev/Authenticated/v0.1
	PayloadAccessRequest                    // granted.dev/AccessRequest/v0.1
	PayloadDecision                         // granted.dev/Decision/v0.1
	PayloadGrantCreated                     // granted.dev/GrantCreated/v0.1
)
