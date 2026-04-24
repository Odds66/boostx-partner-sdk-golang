package handlers

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides the keys needed by every handler the SDK mounts:
// public keys for verifying inbound tokens and the partner private key for
// signing the /verify-keys response.
type KeyStore interface {
	// PartnerPublicKey returns the partner's public key for verifying GID signatures.
	PartnerPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)

	// PartnerPrivateKey returns the partner's private key for signing /verify-keys responses.
	PartnerPrivateKey(ctx context.Context, partner, user, bet string) (*ecdsa.PrivateKey, error)

	// BoostxPublicKey returns the Boostx public key for verifying Booster, CheckBet, and VerifyKeys tokens.
	BoostxPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)
}
