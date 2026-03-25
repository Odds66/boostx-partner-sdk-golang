package keys

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

// StaticKeyStore is a simple key store that holds fixed public keys.
type StaticKeyStore struct {
	gamepassKey *ecdsa.PublicKey
	boosterKey  *ecdsa.PublicKey
}

// NewStaticKeyStore creates a StaticKeyStore with fixed public keys.
// Returns an error if either key is nil.
func NewStaticKeyStore(gamepassKey, boosterKey *ecdsa.PublicKey) (*StaticKeyStore, error) {
	if gamepassKey == nil {
		return nil, errors.New("gamepassKey cannot be nil")
	}
	if boosterKey == nil {
		return nil, errors.New("boosterKey cannot be nil")
	}
	return &StaticKeyStore{
		gamepassKey: gamepassKey,
		boosterKey:  boosterKey,
	}, nil
}

// LoadFromFiles creates a StaticKeyStore by loading public keys from files.
func LoadFromFiles(gamepassKeyPath, boosterKeyPath string) (*StaticKeyStore, error) {
	gamepassKey, err := LoadPublicKeyFromFile(gamepassKeyPath)
	if err != nil {
		return nil, err
	}

	boosterKey, err := LoadPublicKeyFromFile(boosterKeyPath)
	if err != nil {
		return nil, err
	}

	return NewStaticKeyStore(gamepassKey, boosterKey)
}

// LoadFromPEM creates a StaticKeyStore by parsing PEM-encoded public keys.
func LoadFromPEM(gamepassPEM, boosterPEM []byte) (*StaticKeyStore, error) {
	gamepassKey, err := LoadPublicKeyFromPEM(gamepassPEM)
	if err != nil {
		return nil, err
	}

	boosterKey, err := LoadPublicKeyFromPEM(boosterPEM)
	if err != nil {
		return nil, err
	}

	return NewStaticKeyStore(gamepassKey, boosterKey)
}

// GamePassPublicKey returns the gamepass public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticKeyStore) GamePassPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.gamepassKey, nil
}

// BoosterPublicKey returns the booster public key.
// The partner, user, and bet parameters are ignored for static keys.
func (s *StaticKeyStore) BoosterPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return s.boosterKey, nil
}
