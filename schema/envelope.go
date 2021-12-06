package schema

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// BundleInput is the type read by the API. It must be parsed into
// a Bundle by using ParseBundleNoVerification
type BundleInput []Envelope

type Bundle []Envelope

// PrintDebug prints a JSON string of the bundle for debugging.
// It deserialises the payloads so that they are human readable.
func (b *Bundle) PrintDebug() ([]byte, error) {
	debugBundle := []DebugEnvelope{}

	for _, e := range *b {
		debugBundle = append(debugBundle, DebugEnvelope{
			Signatures:  e.Signatures,
			PayloadType: e.PayloadType,
			Payload:     string(e.Payload),
		})
	}

	return json.Marshal(debugBundle)
}

// PrintDebug prints a JSON string of the bundle for debugging.
// It deserialises the payloads so that they are human readable.
// Prints with an idented JSON.
func (b *Bundle) PrintDebugIndent() ([]byte, error) {
	debugBundle := []DebugEnvelope{}

	for _, e := range *b {
		debugBundle = append(debugBundle, DebugEnvelope{
			Signatures:  e.Signatures,
			PayloadType: e.PayloadType,
			Payload:     string(e.Payload),
		})
	}

	return json.MarshalIndent(debugBundle, "", "  ")
}

type Envelope struct {
	Signatures  []Signature `json:"signatures"`
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
}

// DebugEnvelope is the same as Envelope, but with a string payload instead
// of []byte. This allows us to print a human-readable form of the payload
// when debugging, without requiring individually base64-decoding the payloads.
// Don't use this other than for debugging - for sending messages to or from
// the signing services, use the regular Envelope.
type DebugEnvelope struct {
	Signatures  []Signature `json:"signatures"`
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
}

type Signature []byte

type ErrMissingSignatures struct {
	MissingKeys []ecdsa.PublicKey
}

func (e *ErrMissingSignatures) Error() string {
	encodedKeys := []string{}
	for _, key := range e.MissingKeys {
		var keyString string
		enc, err := x509.MarshalPKIXPublicKey(&key)
		if err != nil {
			keyString = "error"
		} else {
			keyString = base64.StdEncoding.EncodeToString(enc)
		}
		encodedKeys = append(encodedKeys, keyString)
	}

	return fmt.Sprintf("missing signatures from %s", strings.Join(encodedKeys, ", "))
}

func (e *Envelope) VerifySignatures(expected []ecdsa.PublicKey) error {
	missingKeys := []ecdsa.PublicKey{}

	for _, key := range expected {
		var matchedKey bool
		var err error
		for _, sig := range e.Signatures {
			matchedKey, err = VerifyECDSA(e.Payload, sig, &key)
			if err != nil {
				return err
			}
			if matchedKey {
				break
			}
		}
		if !matchedKey {
			missingKeys = append(missingKeys, key)
		}
	}

	if len(missingKeys) > 0 {
		return &ErrMissingSignatures{
			MissingKeys: missingKeys,
		}
	}

	return nil
}

func (e *Envelope) ToString() (string, error) {
	payloadStr := string(e.Payload)

	obj := struct {
		Signatures []Signature `json:"signatures"`
		Payload    string      `json:"payload"`
	}{
		Payload:    payloadStr,
		Signatures: e.Signatures,
	}

	res, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return string(res), nil
}

func EnvelopeFromPayload(p Payload) (Envelope, error) {
	serialized, err := p.MarshalJSON()
	if err != nil {
		return Envelope{}, err
	}

	e := Envelope{
		PayloadType: "application/granted+json",
		Payload:     serialized,
	}

	return e, nil
}

func (e *Envelope) Sign(ctx context.Context, signer EnvelopeSigner) error {
	sig, err := signer.Sign(ctx, e.Payload)
	if err != nil {
		return err
	}

	e.Signatures = append(e.Signatures, sig)
	return nil
}

// VerifyECDSA verifies an ECDSA signature.
// It first parses R and S coefficients from the signature.
func VerifyECDSA(singingString, sig []byte, pubKey *ecdsa.PublicKey) (bool, error) {
	keySize := 32
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	hasher := crypto.SHA256.New()
	_, err := hasher.Write(singingString)
	if err != nil {
		return false, err
	}
	hashedSigningString := hasher.Sum(nil)

	valid := ecdsa.Verify(pubKey, hashedSigningString, r, s)
	return valid, nil
}
