package schema

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
)

// EnvelopeSigner signs payloads with a cryptographic signature
type EnvelopeSigner interface {
	// Sign a byte array payload. Returns the signature if successful
	Sign(ctx context.Context, payload []byte) ([]byte, error)
}

type LocalSigner struct {
	PrivateKey *ecdsa.PrivateKey
}

func (l *LocalSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	hash := crypto.SHA256
	hasher := hash.New()
	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	hashedSigningString := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, l.PrivateKey, hashedSigningString)
	if err != nil {
		return nil, err
	}

	curveBits := l.PrivateKey.Curve.Params().BitSize
	expectedCurveBits := 256
	if expectedCurveBits != curveBits {
		return nil, errors.New("invalid curve bits on signing key")
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
	s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

	return out, nil
}
