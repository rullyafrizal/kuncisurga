package kuncisurga

import (
	"context"
	"encoding/pem"
	"testing"
)

// TestNewGenerator tests the NewGenerator function.
func TestNewGenerator(t *testing.T) {
	tests := []struct {
		name     string
		options  []Option
		expected int
	}{
		{"DefaultBitSize", nil, DefaultBitSize},
		{"CustomBitSize", []Option{func(g *Generator) { g.BitSize = 4096 }}, 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator(tt.options...)
			if gen.BitSize != tt.expected {
				t.Errorf("Expected bit size %d, got %d", tt.expected, gen.BitSize)
			}
		})
	}
}

// TestGenerateRawKeyPair tests the GenerateRawKeyPair method.
func TestGenerateRawKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
	}{
		{"DefaultBitSize", DefaultBitSize},
		{"CustomBitSize", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &Generator{BitSize: tt.bitSize}
			ctx := context.Background()
			keyPair, err := gen.GenerateRawKeyPair(ctx)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if keyPair.Private == nil {
				t.Error("Expected private key to be non-nil")
			}
			if keyPair.Public == nil {
				t.Error("Expected public key to be non-nil")
			}
		})
	}
}

// TestGenerateEncodedKeyPair tests the GenerateEncodedKeyPair method.
func TestGenerateEncodedKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
	}{
		{"DefaultBitSize", DefaultBitSize},
		{"CustomBitSize", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &Generator{BitSize: tt.bitSize}
			ctx := context.Background()
			keyPairEncoded, err := gen.GenerateEncodedKeyPair(ctx)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if len(keyPairEncoded.Private) == 0 {
				t.Error("Expected private key to be non-empty")
			}
			if len(keyPairEncoded.Public) == 0 {
				t.Error("Expected public key to be non-empty")
			}
		})
	}
}

// TestGeneratePEMKeyPair tests the GeneratePEMKeyPair method.
func TestGeneratePEMKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
	}{
		{"DefaultBitSize", DefaultBitSize},
		{"CustomBitSize", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &Generator{BitSize: tt.bitSize}
			ctx := context.Background()
			keyPairPEM, err := gen.GeneratePEMKeyPair(ctx)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if len(keyPairPEM.Private) == 0 {
				t.Error("Expected private key PEM to be non-empty")
			}
			if len(keyPairPEM.Public) == 0 {
				t.Error("Expected public key PEM to be non-empty")
			}

			block, _ := pem.Decode(keyPairPEM.Private)
			if block == nil || block.Type != "RSA PRIVATE KEY" {
				t.Error("Expected private key PEM to contain RSA PRIVATE KEY block")
			}

			block, _ = pem.Decode(keyPairPEM.Public)
			if block == nil || block.Type != "RSA PUBLIC KEY" {
				t.Error("Expected public key PEM to contain RSA PUBLIC KEY block")
			}
		})
	}
}
