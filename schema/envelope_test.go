package schema

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifySignaturesWorks(t *testing.T) {
	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey

	e := Envelope{
		Payload: []byte("test"),
	}
	err = e.Sign(ctx, &LocalSigner{PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	err = e.VerifySignatures([]ecdsa.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignaturesReturnsError(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey

	e := Envelope{
		Payload: []byte("test"),
	}
	err = e.VerifySignatures([]ecdsa.PublicKey{pub})
	target := &ErrMissingSignatures{}
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, target.MissingKeys, []ecdsa.PublicKey{pub})
}
