// Package tokens provides JWT token types (GamePass, Booster, CheckBet, Settlement)
// and ES256 signing/parsing for the BoostX partner integration.
package tokens

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Booster contains the parsed Booster token along with the extracted GID.
type Booster struct {
	GID // Embedded GID fields (Partner, User, Bet, Signature)

	Round   int     // Round number
	Boost   float64 // Boost multiplier
	Final   bool    // Whether this is the final boost
	Jackpot bool    // Whether jackpot was triggered
}

// CalculateFinalCoefficient returns the raw 1 + (x - 1) * boost, without fused
// multiply-add, as BoostX computes it. PlayerX gives the X the player saw.
func CalculateFinalCoefficient(x, boost float64) float64 {
	return 1 + float64((x-1)*boost) // the conversion stops FMA fusion on arm64 and others
}

// FloorX floors x to decimals places as BoostX does, rounding x * 10^decimals
// to 15 significant digits first. decimals: 0 (treated as 2) or 2–6.
func FloorX(x float64, decimals int) float64 {
	if decimals == 0 {
		decimals = 2
	}
	scale := math.Pow10(decimals)
	scaled, _ := strconv.ParseFloat(strconv.FormatFloat(x*scale, 'g', 15, 64), 64)
	return math.Floor(scaled) / scale
}

// PlayerX returns the X the player saw for a bet's xBase (xrange.init), a
// Booster's boost and the bet's xrange.decimals. BoostX floors xBase first.
func PlayerX(xBase, boost float64, decimals int) float64 {
	return FloorX(CalculateFinalCoefficient(FloorX(xBase, decimals), boost), decimals)
}

// boosterPayload contains the fields nested under the "booster" root.
type boosterPayload struct {
	GID     GID     `json:"gid"`
	Round   int     `json:"round"`
	Boost   float64 `json:"boost"`
	Final   bool    `json:"final"`
	Jackpot bool    `json:"jackpot"`
}

// boosterClaims represents the full JWT payload for a Booster token.
type boosterClaims struct {
	Booster boosterPayload `json:"booster"`
	RegisteredClaims
}

// ExtractBoosterPartner extracts the partner_id from a Booster token without verification.
// WARNING: Use only for key lookup. Always verify with ParseBoosterToken afterwards.
func ExtractBoosterPartner(boosterToken string) (string, error) {
	var claims boosterClaims
	if err := ExtractJWTClaims(boosterToken, &claims); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidBooster, err)
	}
	partner := claims.Booster.GID.Partner
	if partner == "" {
		return "", fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}
	return partner, nil
}

// ParseBoosterToken parses a Booster token and verifies both the JWT signature
// and the embedded GID signature.
func ParseBoosterToken(
	boosterToken string,
	boostxPublicKey *ecdsa.PublicKey,
	partnerPublicKey *ecdsa.PublicKey,
) (*Booster, error) {
	if partnerPublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	bc, err := parseBoosterClaims(boosterToken, boostxPublicKey)
	if err != nil {
		return nil, err
	}

	gid := &bc.Booster.GID
	if gid.Partner == "" {
		return nil, fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}

	// Verify GID signature with partner key
	if err := VerifyGID(gid, partnerPublicKey); err != nil {
		return nil, fmt.Errorf("failed to verify GID: %w", err)
	}

	return &Booster{
		GID:     *gid,
		Round:   bc.Booster.Round,
		Boost:   bc.Booster.Boost,
		Final:   bc.Booster.Final,
		Jackpot: bc.Booster.Jackpot,
	}, nil
}

// parseBoosterClaims parses and validates a Booster JWT token from BoostX.
func parseBoosterClaims(tokenString string, boostxPublicKey *ecdsa.PublicKey) (*boosterClaims, error) {
	if boostxPublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	var claims boosterClaims
	if err := ParseJWT(tokenString, &claims, boostxPublicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidBooster, err)
	}

	return &claims, nil
}
