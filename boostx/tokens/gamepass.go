package tokens

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"time"
)

// GamePass represents the parsed claims from a GamePass JWT token.
// This token is created by the Partner and sent to BoostX.
type GamePass struct {
	GID                          // Embedded GID fields (Partner, User, Bet, Signature)
	Amount         float64       // Stake amount
	Currency       string        // Currency code (e.g., "USD", "EUR")
	X              float64       // Initial coefficient (xrange.init)
	XMin           float64       // Minimum coefficient (xrange.min)
	XMax           float64       // Maximum coefficient (xrange.max)
	EventName      string        // Optional event name
	EventMarket    string        // Optional event market
	EventSelection string        // Optional event selection
	RegisteredClaims
}

// GamePassParams contains the parameters for creating a GamePass token.
type GamePassParams struct {
	Partner        string
	User           string
	Bet            string
	Amount         float64
	Currency       string
	X              float64
	XMin           float64
	XMax           float64
	EventName      string // optional
	EventMarket    string // optional
	EventSelection string // optional
}

// Internal serialization types for the nested JWT payload.

type stakeClaims struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type xRangeClaims struct {
	Init float64 `json:"init"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
}

type eventClaims struct {
	Name      string `json:"name"`
	Market    string `json:"market"`
	Selection string `json:"selection"`
}

type gamePassPayload struct {
	GID    GID          `json:"gid"`
	Stake  stakeClaims  `json:"stake"`
	XRange xRangeClaims `json:"xrange"`
	Event  *eventClaims `json:"event,omitempty"`
}

type gamePassClaims struct {
	GamePass gamePassPayload `json:"gamepass"`
	RegisteredClaims
}

// CreateGamePassToken creates a new GamePass JWT token signed with the partner's private key.
// It builds a GID, then embeds it in the nested gamepass payload.
func CreateGamePassToken(privateKey *ecdsa.PrivateKey, params GamePassParams) (string, error) {
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
	if params.Currency == "" {
		return "", fmt.Errorf("%w: currency", ErrMissingClaim)
	}

	// Validate numeric fields
	if params.Amount < 0 || math.IsNaN(params.Amount) || math.IsInf(params.Amount, 0) {
		return "", fmt.Errorf("%w: amount", ErrInvalidClaim)
	}
	if params.X < 0 || math.IsNaN(params.X) || math.IsInf(params.X, 0) {
		return "", fmt.Errorf("%w: x", ErrInvalidClaim)
	}
	if params.XMin < 0 || math.IsNaN(params.XMin) || math.IsInf(params.XMin, 0) {
		return "", fmt.Errorf("%w: xmin", ErrInvalidClaim)
	}
	if params.XMax < 0 || math.IsNaN(params.XMax) || math.IsInf(params.XMax, 0) {
		return "", fmt.Errorf("%w: xmax", ErrInvalidClaim)
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
				Init: params.X,
				Min:  params.XMin,
				Max:  params.XMax,
			},
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	if params.EventName != "" || params.EventMarket != "" || params.EventSelection != "" {
		claims.GamePass.Event = &eventClaims{
			Name:      params.EventName,
			Market:    params.EventMarket,
			Selection: params.EventSelection,
		}
	}

	return SignJWT(claims, privateKey)
}

// ExtractGamePassClaims extracts GamePass claims without verifying the signature.
// WARNING: Use only for key lookup. Always verify with ParseGamePassToken afterwards.
func ExtractGamePassClaims(tokenString string) (*GamePass, error) {
	var claims gamePassClaims
	if err := ExtractJWTClaims(tokenString, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGamePass, err)
	}

	gp := &claims.GamePass
	if gp.GID.Partner == "" {
		return nil, fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}

	var eventName, eventMarket, eventSelection string
	if gp.Event != nil {
		eventName = gp.Event.Name
		eventMarket = gp.Event.Market
		eventSelection = gp.Event.Selection
	}

	return &GamePass{
		GID:              gp.GID,
		Amount:           gp.Stake.Amount,
		Currency:         gp.Stake.Currency,
		X:                gp.XRange.Init,
		XMin:             gp.XRange.Min,
		XMax:             gp.XRange.Max,
		EventName:        eventName,
		EventMarket:      eventMarket,
		EventSelection:   eventSelection,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}

// ParseGamePassToken parses and validates a GamePass JWT token,
// including verification of the embedded GID signature.
// A single key is used because the partner signs both the outer JWT and the GID.
// This differs from ParseBoosterToken/ParseCheckBetToken where BoostX signs the
// JWT but the partner signed the GID, requiring two separate keys.
func ParseGamePassToken(tokenString string, publicKey *ecdsa.PublicKey) (*GamePass, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	var claims gamePassClaims
	if err := ParseJWT(tokenString, &claims, publicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidGamePass, err)
	}

	gp := &claims.GamePass
	if gp.GID.Partner == "" {
		return nil, fmt.Errorf("%w: gid.partner", ErrMissingClaim)
	}

	// Verify GID signature with same key
	if err := VerifyGID(&gp.GID, publicKey); err != nil {
		return nil, fmt.Errorf("failed to verify GID: %w", err)
	}

	var eventName, eventMarket, eventSelection string
	if gp.Event != nil {
		eventName = gp.Event.Name
		eventMarket = gp.Event.Market
		eventSelection = gp.Event.Selection
	}

	return &GamePass{
		GID:              gp.GID,
		Amount:           gp.Stake.Amount,
		Currency:         gp.Stake.Currency,
		X:                gp.XRange.Init,
		XMin:             gp.XRange.Min,
		XMax:             gp.XRange.Max,
		EventName:        eventName,
		EventMarket:      eventMarket,
		EventSelection:   eventSelection,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}
