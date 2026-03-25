package tokens

import (
	"crypto/ecdsa"
	"fmt"
	"math"
	"time"
)

// Money represents a monetary amount with currency.
type Money struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// Settlement contains the parsed Settlement token with the extracted GID.
// RegisteredClaims is included for when a ParseSettlementToken is added
// (the BoostX backend already parses these tokens).
type Settlement struct {
	GID              // Embedded GID fields (Partner, User, Bet, Signature)
	Result  string   // Bet outcome: "won", "lost", "cancelled", "refunded"
	Payout  Money    // Payout amount and currency
	RegisteredClaims
}

// SettlementParams contains the parameters for creating a Settlement token.
type SettlementParams struct {
	Partner  string
	User     string
	Bet      string
	Result   string  // "won", "lost", "cancelled", "refunded"
	Amount   float64 // Payout amount
	Currency string  // Payout currency (ISO 4217)
}

// settlementPayload contains the fields nested under the "settlement" root.
type settlementPayload struct {
	GID    GID   `json:"gid"`
	Result string `json:"result"`
	Payout Money  `json:"payout"`
}

// settlementClaims represents the full JWT payload for a Settlement token.
type settlementClaims struct {
	Settlement settlementPayload `json:"settlement"`
	RegisteredClaims
}

// validSettlementResults lists the allowed settlement result values.
var validSettlementResults = map[string]bool{
	"won":       true,
	"lost":      true,
	"cancelled": true,
	"refunded":  true,
}

// CreateSettlementToken creates a new Settlement JWT token signed with the partner's private key.
func CreateSettlementToken(privateKey *ecdsa.PrivateKey, params SettlementParams) (string, error) {
	if privateKey == nil {
		return "", ErrInvalidPrivateKey
	}

	// Validate required fields
	if params.Partner == "" {
		return "", fmt.Errorf("%w: partner", ErrMissingClaim)
	}
	if params.User == "" {
		return "", fmt.Errorf("%w: user", ErrMissingClaim)
	}
	if params.Bet == "" {
		return "", fmt.Errorf("%w: bet", ErrMissingClaim)
	}
	if !validSettlementResults[params.Result] {
		return "", fmt.Errorf("%w: result must be won, lost, cancelled, or refunded", ErrInvalidClaim)
	}
	if params.Amount < 0 || math.IsNaN(params.Amount) || math.IsInf(params.Amount, 0) {
		return "", fmt.Errorf("%w: amount", ErrInvalidClaim)
	}
	if params.Currency == "" {
		return "", fmt.Errorf("%w: currency", ErrMissingClaim)
	}

	// Build GID
	gid, err := BuildGID(params.Partner, params.User, params.Bet, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to build GID: %w", err)
	}

	claims := settlementClaims{
		Settlement: settlementPayload{
			GID:    *gid,
			Result: params.Result,
			Payout: Money{
				Amount:   params.Amount,
				Currency: params.Currency,
			},
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	return SignJWT(claims, privateKey)
}
