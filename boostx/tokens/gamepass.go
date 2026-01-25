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
	Identity            // Embedded identity fields (Partner, User, Bet)
	IdentityJWT string  `json:"-"`        // Raw identity sub-token string
	Amount      float64 `json:"amount"`   // Bet amount
	Currency    string  `json:"currency"` // Currency code (e.g., "USD", "EUR")
	X           float64 `json:"x"`        // Current coefficient
	XMin        float64 `json:"xmin"`     // Minimum coefficient
	XMax        float64 `json:"xmax"`     // Maximum coefficient
	RegisteredClaims
}

// gamePassClaims is the JWT payload for the outer gamepass token.
type gamePassClaims struct {
	IdentityJWT string  `json:"identity"` // Embedded identity JWT
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
	X           float64 `json:"x"`
	XMin        float64 `json:"xmin"`
	XMax        float64 `json:"xmax"`
	RegisteredClaims
}

// CreateGamePassToken creates a new GamePass JWT token signed with the partner's private key.
// It first creates an identity sub-token (no iat), then embeds it in the outer gamepass token.
func CreateGamePassToken(
	privateKey *ecdsa.PrivateKey,
	partner string,
	user string,
	bet string,
	amount float64,
	currency string,
	x float64,
	xmin float64,
	xmax float64,
) (string, error) {
	if privateKey == nil {
		return "", ErrInvalidPrivateKey
	}

	// Validate required fields
	if partner == "" {
		return "", fmt.Errorf("%w: partner", ErrMissingClaim)
	}
	if user == "" {
		return "", fmt.Errorf("%w: user", ErrMissingClaim)
	}
	if bet == "" {
		return "", fmt.Errorf("%w: bet", ErrMissingClaim)
	}

	// Validate numeric fields
	if amount < 0 || math.IsNaN(amount) || math.IsInf(amount, 0) {
		return "", fmt.Errorf("%w: amount", ErrInvalidClaim)
	}
	if x < 0 || math.IsNaN(x) || math.IsInf(x, 0) {
		return "", fmt.Errorf("%w: x", ErrInvalidClaim)
	}
	if xmin < 0 || math.IsNaN(xmin) || math.IsInf(xmin, 0) {
		return "", fmt.Errorf("%w: xmin", ErrInvalidClaim)
	}
	if xmax < 0 || math.IsNaN(xmax) || math.IsInf(xmax, 0) {
		return "", fmt.Errorf("%w: xmax", ErrInvalidClaim)
	}

	// Sign identity sub-token (no iat)
	identityJWT, err := SignIdentityJWT(partner, user, bet, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign identity token: %w", err)
	}

	// Sign outer gamepass token
	claims := gamePassClaims{
		IdentityJWT: identityJWT,
		Amount:      amount,
		Currency:    currency,
		X:           x,
		XMin:        xmin,
		XMax:        xmax,
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
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

	if claims.IdentityJWT == "" {
		return nil, fmt.Errorf("%w: identity", ErrMissingClaim)
	}

	// Extract identity claims without verification
	identity, err := ExtractIdentityClaims(claims.IdentityJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to extract identity: %w", err)
	}

	return &GamePass{
		Identity:    *identity,
		IdentityJWT: claims.IdentityJWT,
		Amount:      claims.Amount,
		Currency:    claims.Currency,
		X:           claims.X,
		XMin:        claims.XMin,
		XMax:        claims.XMax,
	}, nil
}

// ParseGamePassToken parses and validates a GamePass JWT token,
// including verification of the embedded identity sub-token.
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

	if claims.IdentityJWT == "" {
		return nil, fmt.Errorf("%w: identity", ErrMissingClaim)
	}

	// Verify identity sub-token with same key
	identity, err := ParseIdentityJWT(claims.IdentityJWT, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity token: %w", err)
	}

	return &GamePass{
		Identity:         *identity,
		IdentityJWT:      claims.IdentityJWT,
		Amount:           claims.Amount,
		Currency:         claims.Currency,
		X:                claims.X,
		XMin:             claims.XMin,
		XMax:             claims.XMax,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}
