package serveractions

import (
	"github.com/common-fate/attestations/schema"
)

type ServerActor struct {
	signer schema.EnvelopeSigner
}

func New(signer schema.EnvelopeSigner) *ServerActor {
	return &ServerActor{
		signer: signer,
	}
}
