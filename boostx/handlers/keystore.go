package handlers

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides public keys for token verification.
type KeyStore interface {
	// PartnerPublicKey returns the partner's public key for verifying GID signatures.
	PartnerPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)

	// BoostxPublicKey returns the Boostx public key for verifying Booster and CheckBet tokens.
	BoostxPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)
}
