package tokens

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// Boost contains the parsed Boost token along with the extracted Identity.
type Boost struct {
	Identity // Embedded identity fields (Partner, User, Bet)

	Round   int     // Round number
	Boost   float64 // Boost multiplier
	Final   bool    // Whether this is the final boost
	Jackpot bool    // Whether jackpot was triggered
}

// CalculateFinalCoefficient computes the boosted coefficient using the formula:
// X' = 1 + (X - 1) * boost
func CalculateFinalCoefficient(x, boost float64) float64 {
	return 1 + (x-1)*boost
}

// ExtractBoostClaims extracts partner/user/bet from a Boost token without verification.
// WARNING: Use only for key lookup. Always verify with ParseBoostToken afterwards.
func ExtractBoostClaims(boostToken string) (partner, user, bet string, err error) {
	var claims boostClaims
	if err := ExtractJWTClaims(boostToken, &claims); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrInvalidBoost, err)
	}

	if claims.Identity == "" {
		return "", "", "", fmt.Errorf("%w: identity", ErrMissingClaim)
	}

	identity, err := ExtractIdentityClaims(claims.Identity)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to extract embedded identity: %w", err)
	}

	return identity.Partner, identity.User, identity.Bet, nil
}

// ParseBoostToken parses a Boost token and extracts the embedded identity,
// validating both tokens.
func ParseBoostToken(
	boostToken string,
	boostXPublicKey *ecdsa.PublicKey,
	partnerPublicKey *ecdsa.PublicKey,
) (*Boost, error) {
	// Parse and validate the Boost token
	bc, err := parseBoostClaims(boostToken, boostXPublicKey)
	if err != nil {
		return nil, err
	}

	// Extract and validate the embedded identity
	if bc.Identity == "" {
		return nil, fmt.Errorf("%w: identity", ErrMissingClaim)
	}

	identity, err := ParseIdentityJWT(bc.Identity, partnerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded identity: %w", err)
	}

	return &Boost{
		Identity: *identity,
		Round:    bc.Round,
		Boost:    bc.Boost,
		Final:    bc.Final,
		Jackpot:  bc.Jackpot,
	}, nil
}

// boostClaims represents the claims in a Boost JWT token.
type boostClaims struct {
	Identity string  `json:"identity"` // Identity sub-token JWT
	Round    int     `json:"round"`    // Round number
	Boost    float64 `json:"boost"`    // Boost multiplier
	Final    bool    `json:"final"`    // Whether this is the final boost
	Jackpot  bool    `json:"jackpot"`  // Whether jackpot was triggered
	RegisteredClaims
}

// parseBoostClaims parses and validates a Boost JWT token from BoostX.
func parseBoostClaims(tokenString string, boostXPublicKey *ecdsa.PublicKey) (*boostClaims, error) {
	if boostXPublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	var claims boostClaims
	if err := ParseJWT(tokenString, &claims, boostXPublicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidBoost, err)
	}

	return &claims, nil
}
