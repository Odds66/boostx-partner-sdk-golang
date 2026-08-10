package client

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides private keys for signing outbound tokens.
//
// The partner argument is the BoostX-assigned partner_id (gid.partner in
// inbound tokens); return an error for an unknown id, never a default key.
type KeyStore interface {
	// PartnerPrivateKey returns the partner's private key for signing tokens.
	PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)
}
