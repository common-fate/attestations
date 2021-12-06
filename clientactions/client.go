package clientactions

import (
	"github.com/common-fate/attestations/schema"
)

type ClientActor struct {
	signer schema.EnvelopeSigner
}

func New(signer schema.EnvelopeSigner) *ClientActor {
	return &ClientActor{
		signer: signer,
	}
}
