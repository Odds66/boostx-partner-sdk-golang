package handlers

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides public keys for token verification.
type KeyStore interface {
	// GamePassPublicKey returns the public key for verifying GamePass tokens.
	GamePassPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)

	// BoostPublicKey returns the public key for verifying Boost tokens.
	BoostPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)
}
