package tokens

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// jwtHeader represents a JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// RegisteredClaims contains the standard JWT claims.
type RegisteredClaims struct {
	IssuedAt int64 `json:"iat,omitempty"`
}

// SignJWT creates a signed JWT token using ES256 (ECDSA P-256 + SHA-256).
func SignJWT(claims any, privateKey *ecdsa.PrivateKey) (string, error) {
	// Encode header
	header := jwtHeader{Alg: "ES256", Typ: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64URLEncode(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	payloadB64 := base64URLEncode(payloadJSON)

	// Create signature input
	signingInput := headerB64 + "." + payloadB64

	// Sign with ECDSA
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Encode signature as R || S (each padded to 32 bytes for P-256)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)
	signatureB64 := base64URLEncode(signature)

	return signingInput + "." + signatureB64, nil
}

// ParseJWT parses and verifies a JWT token, unmarshaling claims into the provided struct.
func ParseJWT(tokenString string, claims any, publicKey *ecdsa.PublicKey) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// Decode and verify header
	headerJSON, err := base64URLDecode(headerB64)
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	if header.Alg != "ES256" {
		return fmt.Errorf("%w: expected ES256, got %s", ErrInvalidSignature, header.Alg)
	}

	// Verify signature
	signature, err := base64URLDecode(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signature) != 64 {
		return fmt.Errorf("%w: invalid signature length", ErrInvalidSignature)
	}

	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return ErrInvalidSignature
	}

	// Decode payload
	payloadJSON, err := base64URLDecode(payloadB64)
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	if err := json.Unmarshal(payloadJSON, claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	return nil
}

// ExtractJWTClaims extracts claims from a JWT without verifying the signature.
// WARNING: This should only be used to get identifiers for key lookup.
// Always verify the token afterwards with ParseJWT.
func ExtractJWTClaims(tokenString string, claims any) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	if err := json.Unmarshal(payloadJSON, claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	return nil
}

// base64URLEncode encodes data using base64url encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes base64url encoded data (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Handle both padded and unpadded input
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(s)
}
