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

	// defaultVerifyKeysSkew is the iat skew window applied when a verify-keys
	// token is parsed with maxSkew == 0.
	defaultVerifyKeysSkew = 30 * time.Second
)

// VerifyKeysRequest contains the parsed claims of a BoostX → partner
// verify-keys request. PartnerID is the partner the request is addressed to
// (the "aud" claim — "iss" is always "boostx").
type VerifyKeysRequest struct {
	PartnerID string
	Nonce     int32
	RegisteredClaims
}

// VerifyKeysResponse contains the parsed claims of a partner → BoostX
// verify-keys response. PartnerID is the partner that signed the response
// (the "iss" claim — "aud" is always "boostx").
type VerifyKeysResponse struct {
	PartnerID string
	Nonce     int32
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

// validatePartnerID rejects partner identifiers that cannot legally appear in a
// verify-keys token: empty, or equal to BoostxIdentity. A partner named
// "boostx" would make a request's claims ({iss:"boostx", aud:"boostx"}) and a
// response's claims identical, collapsing the two directions into one — so the
// signing key would become the only thing telling them apart.
func validatePartnerID(partnerID string) error {
	switch partnerID {
	case "":
		return fmt.Errorf("%w: partnerID", ErrMissingClaim)
	case BoostxIdentity:
		return fmt.Errorf("%w: partnerID must not be %q", ErrInvalidClaim, BoostxIdentity)
	}
	return nil
}

// CreateVerifyKeysRequestToken signs the BoostX → partner verify-keys request:
// iss="boostx", aud=partnerID. partnerID must be non-empty and not "boostx";
// nonce must be strictly positive.
func CreateVerifyKeysRequestToken(boostxPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	if err := validatePartnerID(partnerID); err != nil {
		return "", err
	}
	return createVerifyKeysToken(boostxPriv, BoostxIdentity, partnerID, nonce)
}

// CreateVerifyKeysResponseToken signs the partner → BoostX verify-keys response:
// iss=partnerID, aud="boostx". partnerID must be non-empty and not "boostx";
// nonce echoes the request nonce and must be strictly positive.
func CreateVerifyKeysResponseToken(partnerPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	if err := validatePartnerID(partnerID); err != nil {
		return "", err
	}
	return createVerifyKeysToken(partnerPriv, partnerID, BoostxIdentity, nonce)
}

// createVerifyKeysToken creates and signs a verify-keys JWT with the given iss/aud/nonce.
func createVerifyKeysToken(privateKey *ecdsa.PrivateKey, issuer, audience string, nonce int32) (string, error) {
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

// ExtractVerifyKeysRequestPartner returns the partner ID (the "aud" claim) from
// an unverified BoostX → partner verify-keys request, for key lookup.
// WARNING: Use only for key lookup. Always verify with ParseVerifyKeysRequestToken afterwards.
func ExtractVerifyKeysRequestPartner(token string) (string, error) {
	var claims verifyKeysClaims
	if err := ExtractJWTClaims(token, &claims); err != nil {
		return "", fmt.Errorf("%w (%v)", ErrVerifyKeysShape, err)
	}
	// Empty aud, or aud=="boostx" (no real partner is the BoostX identity),
	// is a malformed request — reject before any key lookup.
	if claims.Audience == "" || claims.Audience == BoostxIdentity {
		return "", ErrVerifyKeysShape
	}
	return claims.Audience, nil
}

// ParseVerifyKeysRequestToken parses and validates a BoostX → partner
// verify-keys request: expects iss="boostx", aud=partnerID. Verifies the ES256
// signature, checks iat freshness within maxSkew (defaults to 30s when zero),
// and requires a strictly positive nonce. partnerID must be non-empty and not
// "boostx". Returns a sentinel error so callers can map to the protocol reason
// strings via VerifyKeysReason.
func ParseVerifyKeysRequestToken(
	token string,
	boostxPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysRequest, error) {
	if err := validatePartnerID(partnerID); err != nil {
		return nil, err
	}
	claims, err := parseVerifyKeysToken(token, boostxPub, BoostxIdentity, partnerID, maxSkew)
	if err != nil {
		return nil, err
	}
	return &VerifyKeysRequest{
		PartnerID:        claims.Audience,
		Nonce:            claims.VerifyKeys.Nonce,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}

// ParseVerifyKeysResponseToken parses and validates a partner → BoostX
// verify-keys response: expects iss=partnerID, aud="boostx". Same
// signature/freshness/nonce checks as the request path. partnerID must be
// non-empty and not "boostx".
func ParseVerifyKeysResponseToken(
	token string,
	partnerPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysResponse, error) {
	if err := validatePartnerID(partnerID); err != nil {
		return nil, err
	}
	claims, err := parseVerifyKeysToken(token, partnerPub, partnerID, BoostxIdentity, maxSkew)
	if err != nil {
		return nil, err
	}
	return &VerifyKeysResponse{
		PartnerID:        claims.Issuer,
		Nonce:            claims.VerifyKeys.Nonce,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}

// parseVerifyKeysToken parses and validates a verify-keys JWT:
// verifies the ES256 signature, enforces iss/aud match, checks iat freshness
// within maxSkew (defaults to 30s when zero), and requires a strictly positive
// nonce. Returns a sentinel error so callers can map to the protocol reason
// strings (shape / iss-aud / stale / nonce-format / signature).
func parseVerifyKeysToken(
	token string,
	publicKey *ecdsa.PublicKey,
	expectedIssuer, expectedAudience string,
	maxSkew time.Duration,
) (*verifyKeysClaims, error) {
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

	return &claims, nil
}
