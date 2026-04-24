package tokens

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"
)

const (
	// BoostxIdentity is BoostX's identifier in verify-keys JWTs — used as "iss"
	// on requests (BoostX → partner) and as "aud" on responses (partner → BoostX).
	BoostxIdentity = "boostx"

	// nonceMax is the largest valid verify-keys nonce (2^31 − 1). The int32
	// wire type enforces it; exposed only for the create-side error message.
	nonceMax = 0x7FFFFFFF

	// defaultVerifyKeysSkew is the iat skew window applied when
	// ParseVerifyKeysToken is called with maxSkew == 0.
	defaultVerifyKeysSkew = 30 * time.Second
)

// VerifyKeys contains the parsed claims from a verify-keys JWT.
type VerifyKeys struct {
	Issuer   string
	Audience string
	Nonce    int32
	RegisteredClaims
}

// verifyKeysPayload is the wire representation of the "verifyKeys" object.
type verifyKeysPayload struct {
	Nonce int32 `json:"nonce"`
}

// verifyKeysClaims is the full JWT payload for a verify-keys token.
type verifyKeysClaims struct {
	VerifyKeys verifyKeysPayload `json:"verifyKeys"`
	Issuer     string            `json:"iss"`
	Audience   string            `json:"aud"`
	RegisteredClaims
}

// CreateVerifyKeysToken creates and signs a verify-keys JWT with the given iss/aud/nonce.
// nonce must be strictly positive.
func CreateVerifyKeysToken(privateKey *ecdsa.PrivateKey, issuer, audience string, nonce int32) (string, error) {
	if privateKey == nil {
		return "", ErrInvalidPrivateKey
	}
	if issuer == "" {
		return "", fmt.Errorf("%w: iss", ErrMissingClaim)
	}
	if audience == "" {
		return "", fmt.Errorf("%w: aud", ErrMissingClaim)
	}
	if nonce <= 0 {
		return "", fmt.Errorf("%w: nonce must be in (0, %d]", ErrInvalidClaim, nonceMax)
	}

	claims := verifyKeysClaims{
		VerifyKeys: verifyKeysPayload{Nonce: nonce},
		Issuer:     issuer,
		Audience:   audience,
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}
	return SignJWT(claims, privateKey)
}

// ExtractVerifyKeysAudience returns the "aud" claim from an unverified verify-keys token.
// WARNING: Use only for key lookup. Always verify with ParseVerifyKeysToken afterwards.
func ExtractVerifyKeysAudience(token string) (string, error) {
	var claims verifyKeysClaims
	if err := ExtractJWTClaims(token, &claims); err != nil {
		return "", fmt.Errorf("%w (%v)", ErrVerifyKeysShape, err)
	}
	if claims.Audience == "" {
		return "", ErrVerifyKeysShape
	}
	return claims.Audience, nil
}

// ParseVerifyKeysToken parses and validates a verify-keys JWT:
// verifies the ES256 signature, enforces iss/aud match, checks iat freshness
// within maxSkew (defaults to 30s when zero), and requires a strictly positive
// nonce. Returns a sentinel error so callers can map to the protocol reason
// strings (shape / iss-aud / stale / nonce-format / signature).
func ParseVerifyKeysToken(
	token string,
	publicKey *ecdsa.PublicKey,
	expectedIssuer, expectedAudience string,
	maxSkew time.Duration,
) (*VerifyKeys, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if maxSkew < 0 {
		return nil, fmt.Errorf("%w: maxSkew must be >= 0", ErrInvalidClaim)
	}
	if maxSkew == 0 {
		maxSkew = defaultVerifyKeysSkew
	}

	var claims verifyKeysClaims
	if err := ParseJWT(token, &claims, publicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		// Payload failed to decode (malformed JSON, wrong field types,
		// numeric overflow) — treat as malformed shape.
		return nil, fmt.Errorf("%w (%v)", ErrVerifyKeysShape, err)
	}

	if claims.Issuer != expectedIssuer || claims.Audience != expectedAudience {
		return nil, ErrVerifyKeysIssAud
	}

	// Missing iat unmarshals as 0; time.Since(epoch) overshoots any sane skew,
	// so a zero iat falls through the skew check as "stale" — matching the
	// backend's behavior for iat values that are present-but-implausible.
	skew := time.Since(time.Unix(claims.IssuedAt, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > maxSkew {
		return nil, ErrVerifyKeysStale
	}

	// Missing verifyKeys object, missing nonce key, and JSON null all
	// unmarshal to Nonce=0. Strictly-positive nonces are valid; everything
	// else is nonce-format. The int32 wire type caps the upper bound for
	// free — out-of-range values fail unmarshal and land in "shape".
	if claims.VerifyKeys.Nonce <= 0 {
		return nil, ErrVerifyKeysNonce
	}

	return &VerifyKeys{
		Issuer:           claims.Issuer,
		Audience:         claims.Audience,
		Nonce:            claims.VerifyKeys.Nonce,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}
