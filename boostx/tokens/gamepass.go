package tokens

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// GamePass represents the parsed claims from a GamePass JWT token.
// This token is created by the Partner and sent to BoostX.
//
// Deprecated: GamePass, ExtractGamePassClaims and ParseGamePassToken check the
// signatures and the shape of what they read, not whether BoostX accepts the
// gamepass. They are kept for tests.
type GamePass struct {
	GID                // Embedded GID fields (Partner, User, Bet, Signature)
	Amount     float64 // Stake in major units of Currency (12.5, never cents)
	Currency   string  // Currency code (e.g., "USD", "EUR")
	X          float64 // Your own coefficient before the boost (xrange.init), never derived from a boost
	XMin       float64 // Minimum coefficient (xrange.min); 0 = not set
	XMax       float64 // Maximum coefficient (xrange.max); 0 = not set
	XDecimals  int     // Decimal places for X flooring (xrange.decimals); 0 = not set
	EventTitle string  // Optional event title
	Demo       bool    // Marks this as a demo/test session (gamepass.demo)
	RegisteredClaims
}

// GamePassParams contains the parameters for creating a GamePass token. On the
// gamepass that starts a bet, BoostX requires X, XMin and XMax in [1.1, 200] and
// XMin < XMax; the SDK checks only that X is set, that X, XMin and XMax are
// finite and not negative, and that XDecimals is in range.
type GamePassParams struct {
	Partner    string  // Partner identifier assigned by BoostX (matches gid.partner)
	User       string  // User identifier; must not contain ":" (not checked)
	Bet        string  // Bet identifier; must not contain ":" (not checked)
	Amount     float64 // Stake in major units of Currency (12.5, never cents); must be at least 0.01
	Currency   string  // Currency code, 3 or 4 uppercase letters (e.g., "USD", "USDT"), sent as given
	X          float64 // Your own coefficient before the boost (xrange.init), never derived from a boost; must be > 0
	XMin       float64 // Optional minimum coefficient; 0 = omit (defaults to 1.1)
	XMax       float64 // Optional maximum coefficient; 0 = omit (defaults to 200)
	XDecimals  int     // Optional decimal places for X flooring; 0 = omit (defaults to 2), valid range [2, 6]
	EventTitle string  // Optional event title
	Demo       bool    // Optional; true marks a demo/test session (omitted when false)
}

// Internal serialization types for the nested JWT payload.

type stakeClaims struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type xRangeClaims struct {
	Init     float64 `json:"init"`
	Min      float64 `json:"min,omitempty"`
	Max      float64 `json:"max,omitempty"`
	Decimals int     `json:"decimals,omitempty"`
}

type eventClaims struct {
	Title string `json:"title"`
}

type gamePassPayload struct {
	GID    GID          `json:"gid"`
	Stake  stakeClaims  `json:"stake"`
	XRange xRangeClaims `json:"xrange"`
	Event  *eventClaims `json:"event,omitempty"`
	Demo   bool         `json:"demo,omitempty"`
}

type gamePassClaims struct {
	GamePass gamePassPayload `json:"gamepass"`
	RegisteredClaims
}

// CreateGamePassToken creates a new GamePass JWT token signed with the partner's private key.
// It builds a GID, then embeds it in the nested gamepass payload.
func CreateGamePassToken(privateKey *ecdsa.PrivateKey, params GamePassParams) (string, error) {
	if err := checkPrivateKey(privateKey); err != nil {
		return "", err
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
	if params.Currency == "" {
		return "", fmt.Errorf("%w: currency", ErrMissingClaim)
	}
	if !validCurrencyCode(params.Currency) {
		return "", fmt.Errorf("%w: currency must be 3 or 4 uppercase letters", ErrInvalidClaim)
	}

	// Validate numeric fields
	if !(params.Amount >= 0.01) || math.IsInf(params.Amount, 1) {
		return "", fmt.Errorf("%w: amount must be finite and at least 0.01", ErrInvalidClaim)
	}
	if !nonNegativeFinite(params.X) || params.X == 0 {
		return "", fmt.Errorf("%w: x", ErrInvalidClaim)
	}
	if !nonNegativeFinite(params.XMin) {
		return "", fmt.Errorf("%w: xmin", ErrInvalidClaim)
	}
	if !nonNegativeFinite(params.XMax) {
		return "", fmt.Errorf("%w: xmax", ErrInvalidClaim)
	}
	if params.XDecimals != 0 && (params.XDecimals < 2 || params.XDecimals > 6) {
		return "", fmt.Errorf("%w: xdecimals", ErrInvalidClaim)
	}

	// Build GID
	gid, err := BuildGID(params.Partner, params.User, params.Bet, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to build GID: %w", err)
	}

	// Build claims
	claims := gamePassClaims{
		GamePass: gamePassPayload{
			GID: *gid,
			Stake: stakeClaims{
				Amount:   params.Amount,
				Currency: params.Currency,
			},
			XRange: xRangeClaims{
				Init:     params.X,
				Min:      params.XMin,
				Max:      params.XMax,
				Decimals: params.XDecimals,
			},
			Demo: params.Demo,
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	if params.EventTitle != "" {
		claims.GamePass.Event = &eventClaims{Title: params.EventTitle}
	}

	return SignJWT(claims, privateKey)
}

// readGamePass reads a GamePass payload by exact member names. Beyond the gid
// shape it checks only that each member it reads decodes into its field.
func readGamePass(claims map[string]json.RawMessage) (*GamePass, error) {
	root, ok := claims["gamepass"]
	if !ok {
		return nil, fmt.Errorf("%w: gamepass", ErrMissingClaim)
	}
	gp, ok := jsonObject(root)
	if !ok {
		return nil, fmt.Errorf("%w: gamepass is not an object", ErrInvalidClaim)
	}
	gid, err := readGIDClaim(gp["gid"])
	if err != nil {
		return nil, err
	}
	g := &GamePass{GID: gid}
	stake, _ := jsonObject(gp["stake"])
	xrange, _ := jsonObject(gp["xrange"])
	event, _ := jsonObject(gp["event"])
	for _, f := range []struct {
		obj  map[string]json.RawMessage
		name string
		dst  any
	}{
		{stake, "amount", &g.Amount}, {stake, "currency", &g.Currency},
		{xrange, "init", &g.X}, {xrange, "min", &g.XMin}, {xrange, "max", &g.XMax}, {xrange, "decimals", &g.XDecimals},
		{event, "title", &g.EventTitle}, {gp, "demo", &g.Demo}, {claims, "iat", &g.IssuedAt},
	} {
		if raw, ok := f.obj[f.name]; ok {
			if err := json.Unmarshal(raw, f.dst); err != nil {
				return nil, fmt.Errorf("%w: %s", ErrInvalidClaim, f.name)
			}
		}
	}
	return g, nil
}

// ExtractGamePassClaims extracts GamePass claims without verifying the signature.
// WARNING: Use only for key lookup. Always verify with ParseGamePassToken afterwards.
//
// Deprecated: see GamePass.
func ExtractGamePassClaims(tokenString string) (*GamePass, error) {
	claims, err := unverifiedClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGamePass, err)
	}
	gp, err := readGamePass(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGamePass, err)
	}
	return gp, nil
}

// ParseGamePassToken parses and validates a GamePass JWT token,
// including verification of the embedded GID signature.
// A single key is used because the partner signs both the outer JWT and the GID.
// This differs from ParseBoosterToken/ParseCheckBetToken where BoostX signs the
// JWT but the partner signed the GID, requiring two separate keys.
//
// Deprecated: see GamePass.
func ParseGamePassToken(tokenString string, publicKey *ecdsa.PublicKey) (*GamePass, error) {
	if err := checkPublicKey(publicKey); err != nil {
		return nil, err
	}

	claims, err := verifiedClaims(tokenString, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGamePass, err)
	}
	gp, err := readGamePass(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGamePass, err)
	}

	// Verify GID signature with same key
	if err := VerifyGID(&gp.GID, publicKey); err != nil {
		return nil, fmt.Errorf("%w: failed to verify GID: %w", ErrInvalidGamePass, err)
	}
	return gp, nil
}
