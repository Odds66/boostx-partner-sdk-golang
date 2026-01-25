package tokens

import "errors"

var (
	// Key errors
	ErrInvalidPrivateKey = errors.New("invalid ECDSA private key")
	ErrInvalidPublicKey  = errors.New("invalid ECDSA public key")

	// Token errors
	ErrInvalidGamePass  = errors.New("invalid GamePass token")
	ErrInvalidBoost     = errors.New("invalid Boost token")
	ErrInvalidIdentity  = errors.New("invalid Identity token")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrMissingClaim     = errors.New("missing required claim")
	ErrInvalidClaim     = errors.New("invalid claim value")
)
