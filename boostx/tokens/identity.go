package tokens

import (
	"crypto/ecdsa"
	"fmt"
)

// Identity represents the claims in an identity sub-token JWT.
// This token is embedded inside both GamePass and Boost JWTs.
type Identity struct {
	Partner string `json:"partner"` // Partner identifier
	User    string `json:"user"`    // User identifier
	Bet     string `json:"bet"`     // Bet identifier
}

// SignIdentityJWT creates a signed identity sub-token JWT (no iat).
func SignIdentityJWT(partner, user, bet string, privateKey *ecdsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", ErrInvalidPrivateKey
	}
	if partner == "" {
		return "", fmt.Errorf("%w: partner", ErrMissingClaim)
	}
	if user == "" {
		return "", fmt.Errorf("%w: user", ErrMissingClaim)
	}
	if bet == "" {
		return "", fmt.Errorf("%w: bet", ErrMissingClaim)
	}

	claims := Identity{
		Partner: partner,
		User:    user,
		Bet:     bet,
	}

	return SignJWT(claims, privateKey)
}

// ParseIdentityJWT parses and verifies an identity sub-token JWT.
func ParseIdentityJWT(identityJWT string, publicKey *ecdsa.PublicKey) (*Identity, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	var claims Identity
	if err := ParseJWT(identityJWT, &claims, publicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
	}

	return &claims, nil
}

// ExtractIdentityClaims extracts identity claims without verification.
// WARNING: Use only for key lookup. Always verify with ParseIdentityJWT afterwards.
func ExtractIdentityClaims(identityJWT string) (*Identity, error) {
	var claims Identity
	if err := ExtractJWTClaims(identityJWT, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
	}
	return &claims, nil
}
