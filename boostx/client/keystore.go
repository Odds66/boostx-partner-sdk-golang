package client

import (
	"context"
	"crypto/ecdsa"
)

// KeyStore provides private keys for signing outbound tokens.
//
// The partner argument is the BoostX-assigned partner_id (gid.partner in
// inbound tokens). Return an error wrapping keys.ErrUnknownPartner
// (boostx.ErrUnknownPartner) for a partner_id you do not serve, never a
// default key; IsRetryable reports it as final.
type KeyStore interface {
	// PartnerPrivateKey returns the partner's private key for signing tokens.
	PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)
}
