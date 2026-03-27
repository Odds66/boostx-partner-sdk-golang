package keys

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// StaticPublicKeyStore is a simple key store that holds fixed public keys.
type StaticPublicKeyStore struct {
	partnerKey *ecdsa.PublicKey
	boostxKey  *ecdsa.PublicKey
}

// NewStaticPublicKeyStore creates a StaticPublicKeyStore with fixed public keys.
// Returns an error if either key is nil.
func NewStaticPublicKeyStore(partnerKey, boostxKey *ecdsa.PublicKey) (*StaticPublicKeyStore, error) {
	if partnerKey == nil {
		return nil, errors.New("partnerKey cannot be nil")
	}
	if boostxKey == nil {
		return nil, errors.New("boostxKey cannot be nil")
	}
	return &StaticPublicKeyStore{
		partnerKey: partnerKey,
		boostxKey:  boostxKey,
	}, nil
}

// LoadFromFiles creates a StaticPublicKeyStore by loading public keys from files.
func LoadFromFiles(partnerKeyPath, boostxKeyPath string) (*StaticPublicKeyStore, error) {
	partnerKey, err := LoadPublicKeyFromFile(partnerKeyPath)
	if err != nil {
		return nil, err
	}

	boostxKey, err := LoadPublicKeyFromFile(boostxKeyPath)
	if err != nil {
		return nil, err
	}

	return NewStaticPublicKeyStore(partnerKey, boostxKey)
}

// LoadFromPEM creates a StaticPublicKeyStore by parsing PEM-encoded public keys.
func LoadFromPEM(partnerPEM, boostxPEM []byte) (*StaticPublicKeyStore, error) {
	partnerKey, err := LoadPublicKeyFromPEM(partnerPEM)
	if err != nil {
		return nil, err
	}

	boostxKey, err := LoadPublicKeyFromPEM(boostxPEM)
	if err != nil {
		return nil, err
	}

	return NewStaticPublicKeyStore(partnerKey, boostxKey)
}

// PartnerPublicKey returns the partner public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticPublicKeyStore) PartnerPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.partnerKey, nil
}

// BoostxPublicKey returns the Boostx public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticPublicKeyStore) BoostxPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.boostxKey, nil
}

// StaticPrivateKeyStore holds a single private key for all signing operations.
type StaticPrivateKeyStore struct {
	key *ecdsa.PrivateKey
}

// NewStaticPrivateKeyStore creates a StaticPrivateKeyStore with the given key.
// Returns an error if key is nil.
func NewStaticPrivateKeyStore(key *ecdsa.PrivateKey) (*StaticPrivateKeyStore, error) {
	if key == nil {
		return nil, fmt.Errorf("private key must not be nil")
	}
	return &StaticPrivateKeyStore{key: key}, nil
}

// PartnerPrivateKey returns the stored private key, ignoring partner/user/bet.
func (s *StaticPrivateKeyStore) PartnerPrivateKey(_ context.Context, _, _, _ string) (*ecdsa.PrivateKey, error) {
	return s.key, nil
}

// StaticKeyStore combines StaticPublicKeyStore and StaticPrivateKeyStore into a
// single store that provides both public keys (for verifying inbound tokens) and
// a private key (for signing outbound tokens).
type StaticKeyStore struct {
	StaticPublicKeyStore
	StaticPrivateKeyStore
}

// NewStaticKeyStore creates a StaticKeyStore holding both public and private keys.
// Returns an error if any key is nil.
func NewStaticKeyStore(partnerKey, boostxKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (*StaticKeyStore, error) {
	pub, err := NewStaticPublicKeyStore(partnerKey, boostxKey)
	if err != nil {
		return nil, err
	}
	priv, err := NewStaticPrivateKeyStore(privateKey)
	if err != nil {
		return nil, err
	}
	return &StaticKeyStore{
		StaticPublicKeyStore:  *pub,
		StaticPrivateKeyStore: *priv,
	}, nil
}
