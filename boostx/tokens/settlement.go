package tokens

import (
	"crypto/ecdsa"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Money represents a monetary amount with currency.
type Money struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// Settlement contains the parsed Settlement token with the extracted GID.
type Settlement struct {
	GID                // Embedded GID fields (Partner, User, Bet, Signature)
	Status    string   // Bet outcome, one of the eight settlement statuses
	Payout    Money    // Payout amount and currency
	Version   int64    // Per-bet version, strictly increasing
	XSettle   *float64 // Partner's own base X at settlement; nil when absent or null
	SettledAt int64    // When the partner settled the bet, epoch milliseconds
	RegisteredClaims
}

// SettlementParams contains the parameters for creating a Settlement token.
type SettlementParams struct {
	Partner  string  // Partner identifier assigned by BoostX
	User     string  // User identifier
	Bet      string  // Bet identifier
	Status   string  // Bet outcome: win, lose, cancelled, refund, half_win, half_lose, cashout or unsettled
	Amount   float64 // Payout amount; 0 for a loss, and must be 0 when Status is "unsettled"
	Currency string  // Payout currency: 3 or 4 uppercase letters, e.g. "USD" or "USDT"

	// Version orders repeated settlements of the same bet, highest wins: retry
	// a failed call unchanged, send corrections under a strictly higher version.
	// In [0, 2^53−1]; a millisecond timestamp works.
	Version int64

	// XSettle is the partner's own base X at settlement, before the boost.
	// Optional: nil means "not applicable"; a pointer to 0 is a real
	// coefficient, distinct from nil. Must be finite and >= 0.
	XSettle *float64

	// SettledAt is when the partner settled the bet, in epoch milliseconds:
	// accepted from 1e12 (2001-09-09) up to 24 hours ahead of now.
	SettledAt int64
}

// settlementPayload contains the fields nested under the "settlement" root.
type settlementPayload struct {
	GID     GID    `json:"gid"`
	Status  string `json:"status"`
	Payout  Money  `json:"payout"`
	Version int64  `json:"version"`
	// Pointer: omitempty drops only nil, so an explicit 0 stays on the wire.
	XSettle   *float64 `json:"xSettle,omitempty"`
	SettledAt int64    `json:"settledAt"`
}

// settlementClaims represents the full JWT payload for a Settlement token.
type settlementClaims struct {
	Settlement settlementPayload `json:"settlement"`
	RegisteredClaims
}

const (
	// minSettledAt is the SettledAt floor in epoch ms; it rejects seconds-scale
	// timestamps, which would date to 1970 when read as milliseconds.
	minSettledAt int64 = 1_000_000_000_000

	// maxSettledAtSkew is how far ahead of now SettledAt may be: partner clocks are
	// required to stay in sync with BoostX, so anything further is a caller bug.
	maxSettledAtSkew = 24 * time.Hour

	// maxSafeInteger is the largest integer a JSON number carries exactly (2^53 - 1).
	maxSafeInteger int64 = 1<<53 - 1
)

// statusUnsettled is the one status carrying an extra rule: its payout must be 0.
const statusUnsettled = "unsettled"

// settlementStatuses lists the allowed settlement status values.
var settlementStatuses = []string{
	"win", "lose", "cancelled", "refund", "half_win", "half_lose", "cashout", statusUnsettled,
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
	if !slices.Contains(settlementStatuses, params.Status) {
		return "", fmt.Errorf("%w: status must be one of %s", ErrInvalidClaim, strings.Join(settlementStatuses, ", "))
	}
	if !nonNegativeFinite(params.Amount) {
		return "", fmt.Errorf("%w: amount", ErrInvalidClaim)
	}
	if params.Status == statusUnsettled && params.Amount != 0 {
		return "", fmt.Errorf("%w: amount must be 0 when status is unsettled", ErrInvalidClaim)
	}
	if params.Currency == "" {
		return "", fmt.Errorf("%w: currency", ErrMissingClaim)
	}
	if !validCurrencyCode(params.Currency) {
		return "", fmt.Errorf("%w: currency must be 3 or 4 uppercase letters", ErrInvalidClaim)
	}
	// Zero is a legal version: BoostX accepts [0, 2^53-1]. Rejecting it to catch an unset
	// field would also reject a partner whose counter legitimately starts at 0.
	if params.Version < 0 || params.Version > maxSafeInteger {
		return "", fmt.Errorf("%w: version", ErrInvalidClaim)
	}
	if params.XSettle != nil && !nonNegativeFinite(*params.XSettle) {
		return "", fmt.Errorf("%w: xsettle", ErrInvalidClaim)
	}
	if params.SettledAt == 0 {
		return "", fmt.Errorf("%w: settledAt", ErrMissingClaim)
	}
	// Clocks are required to be in sync with BoostX, so the 24h ceiling is enforced
	// against the local clock; beyond it is a caller bug — most often a micro- or
	// nanosecond-scale timestamp.
	if params.SettledAt < minSettledAt || params.SettledAt > time.Now().Add(maxSettledAtSkew).UnixMilli() {
		return "", fmt.Errorf("%w: settledAt", ErrInvalidClaim)
	}

	// Build GID
	gid, err := BuildGID(params.Partner, params.User, params.Bet, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to build GID: %w", err)
	}

	claims := settlementClaims{
		Settlement: settlementPayload{
			GID:    *gid,
			Status: params.Status,
			Payout: Money{
				Amount:   params.Amount,
				Currency: params.Currency,
			},
			Version:   params.Version,
			XSettle:   params.XSettle,
			SettledAt: params.SettledAt,
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	return SignJWT(claims, privateKey)
}
