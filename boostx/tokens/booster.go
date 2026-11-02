// Package tokens provides JWT token types (GamePass, Booster, CheckBet, Settlement)
// and ES256 signing/parsing for the BoostX partner integration.
package tokens

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// Booster contains the parsed Booster token along with the extracted GID.
type Booster struct {
	GID // Embedded GID fields (Partner, User, Bet, Signature)

	Round    int     // Round number
	Boost    float64 // Boost multiplier
	Final    bool    // Whether this is the final boost
	Jackpot  bool    // Whether jackpot was triggered
	IssuedAt int64   // iat in Unix seconds, as sent; a retry sends the same token
}

// CalculateFinalCoefficient returns the raw 1 + (x - 1) * boost, without fused
// multiply-add, as BoostX computes it. PlayerX gives the X the player saw.
func CalculateFinalCoefficient(x, boost float64) float64 {
	return 1 + float64((x-1)*boost) // the conversion stops FMA fusion on arm64 and others
}

// FloorX floors x to decimals places as BoostX does, rounding x * 10^decimals
// to 15 significant digits first. decimals: 0 (treated as 2) or 2–6; any other
// gives NaN. A non-finite x gives a non-finite result.
func FloorX(x float64, decimals int) float64 {
	if decimals == 0 {
		decimals = 2
	}
	if decimals < 2 || decimals > 6 {
		return math.NaN()
	}
	scale := math.Pow10(decimals)
	scaled, _ := strconv.ParseFloat(strconv.FormatFloat(x*scale, 'g', 15, 64), 64)
	return math.Floor(scaled) / scale
}

// PlayerX returns the X the player saw for a bet's xBase (xrange.init), a
// Booster's boost and the bet's xrange.decimals. BoostX floors xBase first.
// decimals as for FloorX; a non-finite input gives a non-finite result.
func PlayerX(xBase, boost float64, decimals int) float64 {
	return FloorX(CalculateFinalCoefficient(FloorX(xBase, decimals), boost), decimals)
}

// readBooster reads and checks every claim of a Booster payload, leaving the
// GID signature unverified. Extraction and parsing share it.
func readBooster(claims map[string]json.RawMessage) (*Booster, error) {
	root, ok := claims["booster"]
	if !ok {
		return nil, fmt.Errorf("%w: booster", ErrMissingClaim)
	}
	members, ok := jsonObject(root)
	if !ok {
		return nil, fmt.Errorf("%w: booster is not an object", ErrInvalidClaim)
	}
	gid, err := readGIDClaim(members["gid"])
	if err != nil {
		return nil, err
	}
	b := &Booster{GID: gid}

	raw, ok := members["round"]
	if !ok {
		return nil, fmt.Errorf("%w: round", ErrMissingClaim)
	}
	round, ok := jsonInteger(raw)
	if !ok || round < 1 || round > math.MaxInt {
		return nil, fmt.Errorf("%w: round", ErrInvalidClaim)
	}
	b.Round = int(round)

	if raw, ok = members["boost"]; !ok {
		return nil, fmt.Errorf("%w: boost", ErrMissingClaim)
	}
	if b.Boost, ok = jsonNumber(raw); !ok || !(b.Boost > 0) || math.IsInf(b.Boost, 1) {
		return nil, fmt.Errorf("%w: boost", ErrInvalidClaim)
	}

	for _, f := range []struct {
		name string
		dst  *bool
	}{{"final", &b.Final}, {"jackpot", &b.Jackpot}} {
		if raw, ok = members[f.name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingClaim, f.name)
		}
		if *f.dst, ok = jsonBool(raw); !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidClaim, f.name)
		}
	}

	if b.IssuedAt, err = readTimeClaims(claims); err != nil {
		return nil, err
	}
	return b, nil
}

// ExtractBoosterPartner returns gid.partner from a Booster token without
// verifying it, after the same claim checks ParseBoosterToken makes.
// WARNING: Use only for key lookup. Always verify with ParseBoosterToken afterwards.
func ExtractBoosterPartner(boosterToken string) (string, error) {
	claims, err := unverifiedClaims(boosterToken)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBooster, err)
	}
	b, err := readBooster(claims)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBooster, err)
	}
	return b.Partner, nil
}

// ParseBoosterToken parses a Booster token and verifies both the JWT signature
// and the embedded GID signature.
func ParseBoosterToken(
	boosterToken string,
	boostxPublicKey *ecdsa.PublicKey,
	partnerPublicKey *ecdsa.PublicKey,
) (*Booster, error) {
	return ParseBoosterTokenWithKeys(boosterToken, boostxPublicKey, []*ecdsa.PublicKey{partnerPublicKey})
}

// ParseBoosterTokenWithKeys is ParseBoosterToken with several partner public
// keys, the current one first: the GID passes when any of them verifies it.
func ParseBoosterTokenWithKeys(
	boosterToken string,
	boostxPublicKey *ecdsa.PublicKey,
	partnerPublicKeys []*ecdsa.PublicKey,
) (*Booster, error) {
	if err := checkPublicKey(boostxPublicKey); err != nil {
		return nil, err
	}
	if err := checkPublicKeys(partnerPublicKeys); err != nil {
		return nil, err
	}

	claims, err := verifiedClaims(boosterToken, boostxPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBooster, err)
	}
	b, err := readBooster(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBooster, err)
	}

	// Verify GID signature with partner keys
	if err := verifyGIDWithKeys(&b.GID, partnerPublicKeys); err != nil {
		return nil, fmt.Errorf("%w: failed to verify GID: %w", ErrInvalidBooster, err)
	}
	return b, nil
}
