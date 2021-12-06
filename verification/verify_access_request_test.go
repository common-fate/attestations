package verification

import (
	"context"
	"testing"
	"time"

	"github.com/common-fate/attestations/clientactions"
	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/types"
	"github.com/stretchr/testify/assert"
)

func TestAccessRequest(t *testing.T) {
	ctx := context.Background()
	userID := "alice"
	loginTime := time.Now()
	kp, err := MakeTestKeyPairs([]string{"user", "server"})

	if err != nil {
		t.Fatal(err)
	}

	user := clientactions.New(&schema.LocalSigner{PrivateKey: kp["user"].Private})

	testBundle := []TestEnvelope{
		{
			Payload:  schema.NewInitMessage(mustSerializeECDSAPublicKey(kp["user"].Public)),
			SignedBy: []string{"user", "server"},
		},
		{
			Payload: schema.NewAuthenticatedMessage(schema.AuthMessageOpts{
				Time:   loginTime,
				UserID: userID,
				Claims: map[string]interface{}{},
			}),
			SignedBy: []string{"server"},
		},
	}
	bundle, err := ParseTestBundle(testBundle, kp)
	if err != nil {
		t.Fatal(err)
	}

	outBundle, err := user.RequestAccess(ctx, bundle, schema.AccessRequest{
		Role:   "test-role",
		Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// we should have a third envelope added to the bundle
	assert.Equal(t, 3, len(outBundle))

	e := outBundle[2]

	_, err = schema.DeserializePayload(e.Payload, types.PayloadAccessRequest)
	if err != nil {
		t.Fatal(err)
	}
}
