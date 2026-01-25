// Package keys provides utilities for loading ECDSA P-256 keys.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// LoadPrivateKeyFromPEM parses an ECDSA P-256 private key from PEM-encoded data.
func LoadPrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", tokens.ErrInvalidPrivateKey)
	}

	var privateKey *ecdsa.PrivateKey
	var err error

	// Try PKCS#8 format first (BEGIN PRIVATE KEY)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not ECDSA", tokens.ErrInvalidPrivateKey)
		}
	} else {
		// Try EC PRIVATE KEY format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
		}
	}

	// Validate P-256 curve
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must use P-256 curve", tokens.ErrInvalidPrivateKey)
	}

	return privateKey, nil
}

// LoadPrivateKeyFromFile reads and parses an ECDSA P-256 private key from a file.
func LoadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
	}
	return LoadPrivateKeyFromPEM(data)
}

// LoadPublicKeyFromPEM parses an ECDSA P-256 public key from PEM-encoded data.
func LoadPublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", tokens.ErrInvalidPublicKey)
	}

	var publicKey *ecdsa.PublicKey

	// Try PKIX format (BEGIN PUBLIC KEY)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		var ok bool
		publicKey, ok = key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not ECDSA", tokens.ErrInvalidPublicKey)
		}
	} else {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPublicKey, err)
	}

	// Validate P-256 curve
	if publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must use P-256 curve", tokens.ErrInvalidPublicKey)
	}

	return publicKey, nil
}

// LoadPublicKeyFromFile reads and parses an ECDSA P-256 public key from a file.
func LoadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPublicKey, err)
	}
	return LoadPublicKeyFromPEM(data)
}
