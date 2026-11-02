package tokens

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	// BoostxIdentity is BoostX's identifier in verify-keys JWTs — used as "iss"
	// on requests (BoostX → partner) and as "aud" on responses (partner → BoostX).
	BoostxIdentity = "boostx"

	// nonceMax is the largest valid verify-keys nonce (2^31 − 1).
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

// verifyKeysPayload is the "verifyKeys" object of an emitted verify-keys token.
type verifyKeysPayload struct {
	Nonce int32 `json:"nonce"`
}

// verifyKeysClaims is the payload of an emitted verify-keys token.
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
// iss="boostx", aud=partnerID. partnerID must be non-empty, not "boostx" and
// valid UTF-8; nonce must be strictly positive. A test aid: BoostX signs the
// real requests.
func CreateVerifyKeysRequestToken(boostxPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	if err := checkPrivateKey(boostxPriv); err != nil {
		return "", err
	}
	if err := validatePartnerID(partnerID); err != nil {
		return "", err
	}
	return createVerifyKeysToken(boostxPriv, BoostxIdentity, partnerID, nonce)
}

// CreateVerifyKeysResponseToken signs the partner → BoostX verify-keys response:
// iss=partnerID, aud="boostx". partnerID must be non-empty, not "boostx" and
// valid UTF-8; nonce echoes the request nonce and must be strictly positive.
func CreateVerifyKeysResponseToken(partnerPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	if err := checkPrivateKey(partnerPriv); err != nil {
		return "", err
	}
	if err := validatePartnerID(partnerID); err != nil {
		return "", err
	}
	return createVerifyKeysToken(partnerPriv, partnerID, BoostxIdentity, nonce)
}

// createVerifyKeysToken creates and signs a verify-keys JWT with the given iss/aud/nonce.
func createVerifyKeysToken(privateKey *ecdsa.PrivateKey, issuer, audience string, nonce int32) (string, error) {
	if issuer == "" {
		return "", fmt.Errorf("%w: iss", ErrMissingClaim)
	}
	if audience == "" {
		return "", fmt.Errorf("%w: aud", ErrMissingClaim)
	}
	if nonce <= 0 {
		return "", fmt.Errorf("%w: nonce must be in (0, %d]", ErrInvalidClaim, nonceMax)
	}
	// One of issuer and audience is the partner id; json.Marshal would replace
	// invalid UTF-8 with U+FFFD and sign an id other than the caller's.
	if !utf8.ValidString(issuer) || !utf8.ValidString(audience) {
		return "", fmt.Errorf("%w: partnerID is not well-formed Unicode", ErrInvalidClaim)
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

// verifyKeysFields are the claims of an inbound verify-keys payload.
type verifyKeysFields struct {
	issuer, audience string
	issuedAt         int64
	exp, nbf         *float64
	nonce            json.RawMessage // judged after iss, aud and the time claims
}

// readVerifyKeys checks the claim types of a verify-keys payload, each fault
// ErrVerifyKeysShape: iss and aud strings, iat an integer, verifyKeys an
// object, exp and nbf numbers when present. Absent or null iss, aud, iat and
// verifyKeys read as zero values.
func readVerifyKeys(claims map[string]json.RawMessage) (*verifyKeysFields, error) {
	f := &verifyKeysFields{}
	var ok bool
	for _, c := range []struct {
		name string
		dst  *string
	}{{"iss", &f.issuer}, {"aud", &f.audience}} {
		if raw := claims[c.name]; !isNull(raw) {
			if *c.dst, ok = jsonString(raw); !ok {
				return nil, fmt.Errorf("%w: %s is not a string", ErrVerifyKeysShape, c.name)
			}
		}
	}
	if raw := claims["iat"]; !isNull(raw) {
		if f.issuedAt, ok = jsonInteger(raw); !ok {
			return nil, fmt.Errorf("%w: iat is not an integer", ErrVerifyKeysShape)
		}
	}
	if raw := claims["verifyKeys"]; !isNull(raw) {
		members, ok := jsonObject(raw)
		if !ok {
			return nil, fmt.Errorf("%w: verifyKeys is not an object", ErrVerifyKeysShape)
		}
		f.nonce = members["nonce"]
	}
	for _, c := range []struct {
		name string
		dst  **float64
	}{{"exp", &f.exp}, {"nbf", &f.nbf}} {
		if raw, present := claims[c.name]; present {
			v, ok := jsonNumber(raw)
			if !ok {
				return nil, fmt.Errorf("%w: %s is not a number", ErrVerifyKeysShape, c.name)
			}
			*c.dst = new(v)
		}
	}
	return f, nil
}

// isNull reports whether raw is absent or the JSON null.
func isNull(raw json.RawMessage) bool {
	return raw == nil || string(raw) == "null"
}

// ExtractVerifyKeysRequestPartner returns the partner ID (the "aud" claim) from
// an unverified BoostX → partner verify-keys request, for key lookup, after the
// payload and claim-type checks of ParseVerifyKeysRequestToken.
// WARNING: Use only for key lookup. Always verify with ParseVerifyKeysRequestToken afterwards.
func ExtractVerifyKeysRequestPartner(token string) (string, error) {
	claims, err := unverifiedClaims(token)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", ErrVerifyKeysShape, err)
	}
	f, err := readVerifyKeys(claims)
	if err != nil {
		return "", err
	}
	// Empty aud, or aud=="boostx" (no real partner is the BoostX identity),
	// is a malformed request — reject before any key lookup.
	if f.audience == "" || f.audience == BoostxIdentity {
		return "", ErrVerifyKeysShape
	}
	return f.audience, nil
}

// ParseVerifyKeysRequestToken parses and validates a BoostX → partner
// verify-keys request: expects iss="boostx", aud=partnerID. Verifies the ES256
// signature, requires |now - iat| <= maxSkew in whole seconds (30 s when zero),
// exp and nbf in force when present, and a nonce in [1, 2^31-1]. partnerID must
// be non-empty and not "boostx". Returns a sentinel error so callers can map to
// the protocol reason strings via VerifyKeysReason.
func ParseVerifyKeysRequestToken(
	token string,
	boostxPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysRequest, error) {
	if err := checkPublicKey(boostxPub); err != nil {
		return nil, err
	}
	if err := validatePartnerID(partnerID); err != nil {
		return nil, err
	}
	f, nonce, err := parseVerifyKeysToken(token, boostxPub, BoostxIdentity, partnerID, maxSkew)
	if err != nil {
		return nil, err
	}
	return &VerifyKeysRequest{
		PartnerID:        f.audience,
		Nonce:            nonce,
		RegisteredClaims: RegisteredClaims{IssuedAt: f.issuedAt},
	}, nil
}

// ParseVerifyKeysResponseToken parses and validates a partner → BoostX
// verify-keys response: expects iss=partnerID, aud="boostx". Same checks as
// the request path. partnerID must be non-empty and not "boostx". A test aid:
// with maxSkew 0 it accepts no response that BoostX would refuse at that moment.
func ParseVerifyKeysResponseToken(
	token string,
	partnerPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysResponse, error) {
	if err := checkPublicKey(partnerPub); err != nil {
		return nil, err
	}
	if err := validatePartnerID(partnerID); err != nil {
		return nil, err
	}
	f, nonce, err := parseVerifyKeysToken(token, partnerPub, partnerID, BoostxIdentity, maxSkew)
	if err != nil {
		return nil, err
	}
	return &VerifyKeysResponse{
		PartnerID:        f.issuer,
		Nonce:            nonce,
		RegisteredClaims: RegisteredClaims{IssuedAt: f.issuedAt},
	}, nil
}

// parseVerifyKeysToken parses and validates a verify-keys JWT, its key and
// partner ID already checked, in this order: the ES256 signature, the claim
// types (shape), iss and aud (iss-aud), |now - iat| <= maxSkew in whole
// seconds, 30 s when zero, and exp and nbf when present (stale), then a nonce
// in [1, 2^31-1] (nonce-format). Returns a sentinel error so callers can map
// to the protocol reason strings.
func parseVerifyKeysToken(
	token string,
	publicKey *ecdsa.PublicKey,
	expectedIssuer, expectedAudience string,
	maxSkew time.Duration,
) (*verifyKeysFields, int32, error) {
	if maxSkew < 0 {
		return nil, 0, fmt.Errorf("%w: maxSkew must be >= 0", ErrInvalidClaim)
	}
	if maxSkew == 0 {
		maxSkew = defaultVerifyKeysSkew
	}

	claims, err := verifiedClaims(token, publicKey)
	if err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, 0, fmt.Errorf("%w: %w", ErrInvalidVerifyKeys, err)
		}
		return nil, 0, fmt.Errorf("%w (%v)", ErrVerifyKeysShape, err)
	}
	f, err := readVerifyKeys(claims)
	if err != nil {
		return nil, 0, err
	}

	if f.issuer != expectedIssuer || f.audience != expectedAudience {
		return nil, 0, ErrVerifyKeysIssAud
	}

	// |now - iat| <= maxSkew in whole seconds, compared without arithmetic on iat
	// so no value can overflow. A missing iat reads as 0 and is stale.
	now, window := time.Now().Unix(), int64(maxSkew/time.Second)
	if f.issuedAt < now-window || f.issuedAt > now+window {
		return nil, 0, fmt.Errorf("%w: iat outside skew window", ErrVerifyKeysStale)
	}
	if f.exp != nil && *f.exp <= float64(now) {
		return nil, 0, fmt.Errorf("%w: exp is not after the current time", ErrVerifyKeysStale)
	}
	if f.nbf != nil && *f.nbf > float64(now) {
		return nil, 0, fmt.Errorf("%w: nbf is after the current time", ErrVerifyKeysStale)
	}

	nonce, ok := jsonInteger(f.nonce)
	if !ok || nonce < 1 || nonce > nonceMax {
		return nil, 0, ErrVerifyKeysNonce
	}
	return f, int32(nonce), nil
}
