package tokens

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// CheckBet contains the parsed CheckBet token with the extracted GID.
type CheckBet struct {
	GID // Embedded GID fields (Partner, User, Bet, Signature)
}

// checkBetPayload contains the fields nested under the "checkbet" root.
type checkBetPayload struct {
	GID GID `json:"gid"`
}

// checkBetClaims represents the full JWT payload for a CheckBet token.
type checkBetClaims struct {
	CheckBet checkBetPayload `json:"checkbet"`
	RegisteredClaims
}

// ExtractCheckBetClaims extracts partner/user/bet from a CheckBet token without verification.
// WARNING: Use only for key lookup. Always verify with ParseCheckBetToken afterwards.
func ExtractCheckBetClaims(checkBetToken string) (partner, user, bet string, err error) {
	var claims checkBetClaims
	if err := ExtractJWTClaims(checkBetToken, &claims); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrInvalidCheckBet, err)
	}

	gid := &claims.CheckBet.GID
	if gid.Partner == "" {
		return "", "", "", fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}

	return gid.Partner, gid.User, gid.Bet, nil
}

// ParseCheckBetToken parses a CheckBet token and verifies both the JWT signature
// (signed by BoostX's booster key) and the embedded GID signature (signed by partner key).
func ParseCheckBetToken(
	checkBetToken string,
	boosterPublicKey *ecdsa.PublicKey,
	partnerPublicKey *ecdsa.PublicKey,
) (*CheckBet, error) {
	if boosterPublicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if partnerPublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	var claims checkBetClaims
	if err := ParseJWT(checkBetToken, &claims, boosterPublicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidCheckBet, err)
	}

	gid := &claims.CheckBet.GID
	if gid.Partner == "" {
		return nil, fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}

	// Verify GID signature with partner key
	if err := VerifyGID(gid, partnerPublicKey); err != nil {
		return nil, fmt.Errorf("failed to verify GID: %w", err)
	}

	return &CheckBet{
		GID: *gid,
	}, nil
}
