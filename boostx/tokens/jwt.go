package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
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

	signature, err := signES256(privateKey, []byte(signingInput))
	if err != nil {
		return "", err
	}
	signatureB64 := base64URLEncode(signature)

	return signingInput + "." + signatureB64, nil
}

// ParseJWT parses and verifies a JWT token, unmarshaling claims into the provided struct.
func ParseJWT(tokenString string, claims any, publicKey *ecdsa.PublicKey) error {
	if err := checkPublicKey(publicKey); err != nil {
		return err
	}
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

	hash := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	if !verifyES256(publicKey, hash[:], signature) {
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

// signES256 returns the ES256 signature of data as the 64-byte r || s.
func signES256(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privateKey == nil || privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: not a P-256 key", ErrInvalidPrivateKey)
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// checkPublicKey returns ErrInvalidPublicKey for a nil key or one not on P-256.
func checkPublicKey(publicKey *ecdsa.PublicKey) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return ErrInvalidPublicKey
	}
	return nil
}

// checkPublicKeys returns ErrInvalidPublicKey unless some key passes checkPublicKey.
func checkPublicKeys(publicKeys []*ecdsa.PublicKey) error {
	if slices.ContainsFunc(publicKeys, func(k *ecdsa.PublicKey) bool { return checkPublicKey(k) == nil }) {
		return nil
	}
	return ErrInvalidPublicKey
}

// verifyES256 reports whether sig, a 64-byte r || s, signs the SHA-256 digest
// with publicKey, which must have passed checkPublicKey.
func verifyES256(publicKey *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.Verify(publicKey, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
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
