package tokens

import "errors"

var (
	// Key errors
	ErrInvalidPrivateKey = errors.New("invalid ECDSA private key")
	ErrInvalidPublicKey  = errors.New("invalid ECDSA public key")

	// Token errors
	ErrInvalidGamePass   = errors.New("invalid GamePass token")
	ErrInvalidBooster    = errors.New("invalid Booster token")
	ErrInvalidCheckBet   = errors.New("invalid CheckBet token")
	ErrInvalidSettlement = errors.New("invalid Settlement token")
	ErrInvalidGID        = errors.New("invalid GID")
	ErrInvalidSignature  = errors.New("invalid token signature")
	ErrMissingClaim      = errors.New("missing required claim")
	ErrInvalidClaim      = errors.New("invalid claim value")
)
