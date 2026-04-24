package tokens

import (
	"errors"
	"fmt"
)

var (
	// Key errors
	ErrInvalidPrivateKey = errors.New("invalid ECDSA private key")
	ErrInvalidPublicKey  = errors.New("invalid ECDSA public key")

	// Token errors
	ErrInvalidGamePass   = errors.New("invalid GamePass token")
	ErrInvalidBooster    = errors.New("invalid Booster token")
	ErrInvalidCheckBet   = errors.New("invalid CheckBet token")
	ErrInvalidSettlement = errors.New("invalid Settlement token")
	ErrInvalidVerifyKeys = errors.New("invalid VerifyKeys token")
	ErrInvalidGID        = errors.New("invalid GID")
	ErrInvalidSignature  = errors.New("invalid token signature")
	ErrMissingClaim      = errors.New("missing required claim")
	ErrInvalidClaim      = errors.New("invalid claim value")

	// VerifyKeys-specific reasons (for protocol-level error mapping).
	// Each wraps ErrInvalidVerifyKeys so callers can check the generic
	// sentinel to catch any VerifyKeys failure, or a specific one for a
	// reason-level match.
	ErrVerifyKeysShape  = fmt.Errorf("%w: malformed payload shape", ErrInvalidVerifyKeys)
	ErrVerifyKeysIssAud = fmt.Errorf("%w: iss/aud mismatch", ErrInvalidVerifyKeys)
	ErrVerifyKeysStale  = fmt.Errorf("%w: iat outside skew window", ErrInvalidVerifyKeys)
	ErrVerifyKeysNonce  = fmt.Errorf("%w: invalid nonce format", ErrInvalidVerifyKeys)
)

// VerifyKeys protocol reason strings returned in the HTTP error body:
// {"error": "invalid verifyKeysJWT: <reason>"}. The set mirrors the TypeScript
// backend's union type; callers that classify errors should use these constants
// rather than string literals to prevent drift.
const (
	VerifyKeysReasonShape       = "shape"
	VerifyKeysReasonIssAud      = "iss-aud"
	VerifyKeysReasonStale       = "stale"
	VerifyKeysReasonNonceFormat = "nonce-format"
	VerifyKeysReasonSignature   = "signature"
)

// VerifyKeysReason maps a ParseVerifyKeysToken error to its protocol reason
// string. Unclassified errors fall through to "shape" — the safe default for
// anything that failed JSON-level decoding.
func VerifyKeysReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidSignature):
		return VerifyKeysReasonSignature
	case errors.Is(err, ErrVerifyKeysIssAud):
		return VerifyKeysReasonIssAud
	case errors.Is(err, ErrVerifyKeysStale):
		return VerifyKeysReasonStale
	case errors.Is(err, ErrVerifyKeysNonce):
		return VerifyKeysReasonNonceFormat
	default:
		return VerifyKeysReasonShape
	}
}
