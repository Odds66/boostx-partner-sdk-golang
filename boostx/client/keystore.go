package client

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides private keys for signing outbound tokens.
type KeyStore interface {
	// PartnerPrivateKey returns the partner's private key for signing tokens.
	PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)
}
