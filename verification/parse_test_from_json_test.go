package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/common-fate/attestations/schema"
	"github.com/stretchr/testify/assert"
)

func TestParseTestBundle(t *testing.T) {
	kp, err := MakeTestKeyPairs([]string{"user", "server"})
	if err != nil {
		t.Fatal(err)
	}
	pub := kp["user"].Public
	publicDerBytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		t.Fatal(err)
	}

	payload := schema.NewInitMessage(publicDerBytes)

	testBundle := []TestEnvelope{
		{
			Payload:  payload,
			SignedBy: []string{"user"},
		},
	}

	b, err := ParseTestBundle(testBundle, kp)
	if err != nil {
		t.Fatal(err)
	}

	// ECDSA signatures are non-deterministic
	// so rather than testing the payload is exactly what we expect,
	// we should verify that we got a valid signature from it
	expectedEnv, err := schema.EnvelopeFromPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = expectedEnv.Sign(ctx, &schema.LocalSigner{PrivateKey: kp["user"].Private})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedEnv.Payload, b[0].Payload)
	assert.Equal(t, expectedEnv.PayloadType, b[0].PayloadType)

	err = b[0].VerifySignatures([]ecdsa.PublicKey{kp["user"].Public})
	if err != nil {
		t.Fatal(err)
	}
}
