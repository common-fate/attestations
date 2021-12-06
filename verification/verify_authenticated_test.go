package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/common-fate/attestations/clientactions"
	"github.com/common-fate/attestations/schema"
	"github.com/common-fate/attestations/serveractions"
	"github.com/stretchr/testify/assert"
)

func TestAuthProcess(t *testing.T) {
	userID := "alice"
	loginTime := time.Now()
	userPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPriv.PublicKey

	idServerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatal(err)
	}
	idServerPub := idServerPriv.PublicKey

	user := clientactions.New(&schema.LocalSigner{PrivateKey: userPriv})
	server := serveractions.New(&schema.LocalSigner{PrivateKey: idServerPriv})

	facts := schema.Facts{
		Actors: schema.Actors{
			User: schema.User{
				ID:        userID,
				PublicKey: userPub,
			},
			IdentityServer: schema.IdentityServer{
				PublicKey: idServerPub,
			},
		},
	}
	ctx := context.Background()
	// user signs INIT envelope
	bundle, err := user.Init(ctx, userPub)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err = server.Authenticate(ctx, bundle[0], schema.AuthMessageOpts{
		Time:   loginTime,
		UserID: userID,
		Claims: map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}

	a := AuthenticationStage{}
	err = a.Verify(facts, bundle)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthProcessInvalidUserID(t *testing.T) {
	userID := "alice"
	loginTime := time.Now()
	userPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPriv.PublicKey

	idServerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatal(err)
	}
	idServerPub := idServerPriv.PublicKey

	user := clientactions.New(&schema.LocalSigner{PrivateKey: userPriv})
	server := serveractions.New(&schema.LocalSigner{PrivateKey: idServerPriv})

	facts := schema.Facts{
		Actors: schema.Actors{
			User: schema.User{
				ID:        "anotheruser",
				PublicKey: userPub,
			},
			IdentityServer: schema.IdentityServer{
				PublicKey: idServerPub,
			},
		},
	}

	ctx := context.Background()

	// user signs INIT envelope
	bundle, err := user.Init(ctx, userPub)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err = server.Authenticate(ctx, bundle[0], schema.AuthMessageOpts{
		Time:   loginTime,
		UserID: userID,
		Claims: map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}

	a := AuthenticationStage{}
	err = a.Verify(facts, bundle)
	targetErr := &schema.ErrInvalidPayloadContents{}
	assert.ErrorAs(t, err, &targetErr)
	assert.Equal(t, "user ID didn't match", targetErr.Msg)
}

func TestAuthProcessInvalidUserPublicKey(t *testing.T) {
	userID := "alice"
	loginTime := time.Now()
	userPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPriv.PublicKey

	idServerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		t.Fatal(err)
	}
	idServerPub := idServerPriv.PublicKey

	differentKeyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	differentKey := differentKeyPriv.PublicKey

	user := clientactions.New(&schema.LocalSigner{PrivateKey: userPriv})
	server := serveractions.New(&schema.LocalSigner{PrivateKey: idServerPriv})

	facts := schema.Facts{
		Actors: schema.Actors{
			User: schema.User{
				ID:        "anotheruser",
				PublicKey: userPub,
			},
			IdentityServer: schema.IdentityServer{
				PublicKey: idServerPub,
			},
		},
	}

	ctx := context.Background()

	// user signs INIT envelope
	bundle, err := user.Init(ctx, differentKey)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err = server.Authenticate(ctx, bundle[0], schema.AuthMessageOpts{
		Time:   loginTime,
		UserID: userID,
		Claims: map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}

	a := AuthenticationStage{}
	err = a.Verify(facts, bundle)
	targetErr := &schema.ErrInvalidPayloadContents{}
	assert.ErrorAs(t, err, &targetErr)
	assert.Equal(t, targetErr.Msg, "user public key didn't match")
}

// Authentication should be invalid if the trusted server hasn't signed the INIT payload
func TestAuthProcessMissingServerSignature(t *testing.T) {
	userID := "alice"
	loginTime := time.Now()
	kp, err := MakeTestKeyPairs([]string{"user", "server"})

	if err != nil {
		t.Fatal(err)
	}

	testBundle := []TestEnvelope{
		{
			Payload:  schema.NewInitMessage(mustSerializeECDSAPublicKey(kp["user"].Public)),
			SignedBy: []string{"user"},
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

	facts := schema.Facts{
		Actors: schema.Actors{
			User: schema.User{
				ID:        userID,
				PublicKey: kp["user"].Public,
			},
			IdentityServer: schema.IdentityServer{
				PublicKey: kp["server"].Public,
			},
		},
	}

	a := AuthenticationStage{}
	err = a.Verify(facts, bundle)
	targetErr := &schema.ErrMissingSignatures{}
	assert.ErrorAs(t, err, &targetErr)
	assert.Equal(t, []ecdsa.PublicKey{kp["server"].Public}, targetErr.MissingKeys)
}

// panics if the key didn't serialize properly
func mustSerializeECDSAPublicKey(key ecdsa.PublicKey) []byte {
	bytes, err := x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		panic(err)
	}
	return bytes
}
