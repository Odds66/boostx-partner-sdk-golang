package keys

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

// StaticKeyStore is a simple key store that holds fixed public keys.
type StaticKeyStore struct {
	gamepassKey *ecdsa.PublicKey
	boostKey    *ecdsa.PublicKey
}

// NewStaticKeyStore creates a StaticKeyStore with fixed public keys.
// Returns an error if either key is nil.
func NewStaticKeyStore(gamepassKey, boostKey *ecdsa.PublicKey) (*StaticKeyStore, error) {
	if gamepassKey == nil {
		return nil, errors.New("gamepassKey cannot be nil")
	}
	if boostKey == nil {
		return nil, errors.New("boostKey cannot be nil")
	}
	return &StaticKeyStore{
		gamepassKey: gamepassKey,
		boostKey:    boostKey,
	}, nil
}

// LoadFromFiles creates a StaticKeyStore by loading public keys from files.
func LoadFromFiles(gamepassKeyPath, boostKeyPath string) (*StaticKeyStore, error) {
	gamepassKey, err := LoadPublicKeyFromFile(gamepassKeyPath)
	if err != nil {
		return nil, err
	}

	boostKey, err := LoadPublicKeyFromFile(boostKeyPath)
	if err != nil {
		return nil, err
	}

	return NewStaticKeyStore(gamepassKey, boostKey)
}

// LoadFromPEM creates a StaticKeyStore by parsing PEM-encoded public keys.
func LoadFromPEM(gamepassPEM, boostPEM []byte) (*StaticKeyStore, error) {
	gamepassKey, err := LoadPublicKeyFromPEM(gamepassPEM)
	if err != nil {
		return nil, err
	}

	boostKey, err := LoadPublicKeyFromPEM(boostPEM)
	if err != nil {
		return nil, err
	}

	return NewStaticKeyStore(gamepassKey, boostKey)
}

// GamePassPublicKey returns the gamepass public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticKeyStore) GamePassPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.gamepassKey, nil
}

// BoostPublicKey returns the boost public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticKeyStore) BoostPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.boostKey, nil
}
