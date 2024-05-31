package kuncisurga

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// Client is an interface defining methods for generating key pairs in different formats.
type Client interface {
	// GenerateRawKeyPair generates an RSA key pair with raw rsa.PublicKey and rsa.PrivateKey.
	// Returns a KeyPair containing the generated keys, or an error if the generation fails.
	GenerateRawKeyPair(ctx context.Context) (*KeyPair, error)

	// GenerateEncodedKeyPair generates an RSA key pair and encodes them in DER format.
	// Returns a KeyPairEncoded containing the encoded keys, or an error if the generation fails.
	GenerateEncodedKeyPair(ctx context.Context) (*KeyPairEncoded, error)

	// GeneratePEMKeyPair generates an RSA key pair and encodes them in PEM format.
	// Returns a KeyPairEncoded containing the encoded keys in PEM format, or an error if the generation fails.
	GeneratePEMKeyPair(ctx context.Context) (*KeyPairEncoded, error)
}

// Generator is a struct that holds the configuration for key pair generation, such as the bit size.
type Generator struct {
	BitSize int // BitSize is the size of the RSA key in bits.
}

// KeyPair holds the raw RSA public and private keys.
type KeyPair struct {
	Public  *rsa.PublicKey  // Public is the RSA public key.
	Private *rsa.PrivateKey // Private is the RSA private key.
}

// KeyPairEncoded holds the encoded RSA public and private keys in byte slices.
type KeyPairEncoded struct {
	Public  []byte // Public is the encoded RSA public key.
	Private []byte // Private is the encoded RSA private key.
}

// NewGenerator creates a new Generator with the given options.
// The options can be used to configure the Generator, such as setting the bit size.
// If no options are provided, the default bit size is used.
func NewGenerator(opts ...Option) *Generator {
	g := &Generator{
		BitSize: DefaultBitSize,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// GenerateRawKeyPair generates an RSA key pair with the bit size specified in the Generator.
// Returns a KeyPair containing the raw RSA keys, or an error if the generation fails.
func (g *Generator) GenerateRawKeyPair(ctx context.Context) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, g.BitSize)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	return &KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// GenerateEncodedKeyPair generates an RSA key pair and encodes the keys in DER format.
// Returns a KeyPairEncoded containing the encoded keys, or an error if the generation fails.
func (g *Generator) GenerateEncodedKeyPair(ctx context.Context) (*KeyPairEncoded, error) {
	raw, err := g.GenerateRawKeyPair(ctx)
	if err != nil {
		return nil, err
	}

	privateKey := x509.MarshalPKCS1PrivateKey(raw.Private)
	publicKey, err := x509.MarshalPKIXPublicKey(raw.Public)
	if err != nil {
		return nil, err
	}

	return &KeyPairEncoded{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// GeneratePEMKeyPair generates an RSA key pair and encodes the keys in PEM format.
// Returns a KeyPairEncoded containing the encoded keys in PEM format, or an error if the generation fails.
func (g *Generator) GeneratePEMKeyPair(ctx context.Context) (*KeyPairEncoded, error) {
	encodedKeyPair, err := g.GenerateEncodedKeyPair(ctx)
	if err != nil {
		return nil, err
	}
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: encodedKeyPair.Private,
		})
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: encodedKeyPair.Public,
		})

	return &KeyPairEncoded{
		Private: privateKeyPem,
		Public:  publicKeyPem,
	}, nil
}
