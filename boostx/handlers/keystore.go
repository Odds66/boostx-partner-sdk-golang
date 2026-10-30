package handlers

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides the keys needed by every handler the SDK mounts:
// public keys for verifying inbound tokens and the partner private key for
// signing the /verify-keys response.
//
// Implementations must fail for a partner_id they do not serve (wrap
// keys.ErrUnknownPartner), never fall back to a fixed key set. Match partner
// byte for byte (no case-folding, trimming or normalisation): the /verify-keys
// response iss is the id you accepted. Return a key or an error, never neither.
type KeyStore interface {
	// PartnerPublicKey returns the current partner public key, which verifies
	// GID signatures; implement PartnerPublicKeysStore to also accept earlier keys.
	PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error)

	// PartnerPrivateKey returns the partner's private key for signing /verify-keys responses.
	PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)

	// BoostxPublicKey returns the Boostx public key for verifying Booster, CheckBet, and VerifyKeys tokens.
	BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error)
}

// PartnerPublicKeysStore is an optional KeyStore extension: when the store
// implements it, /set-boost and /check-bet accept a GID that any of the keys
// verifies. Return the current key first, then keys of earlier key pairs.
type PartnerPublicKeysStore interface {
	PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error)
}
