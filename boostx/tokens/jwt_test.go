package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func generateCurveKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return privateKey
}

// TestUnusableKeys pins that a key that is nil, zero-valued or off P-256, or a
// private key whose signing fails (D=0), is refused with ErrInvalidPrivateKey
// or ErrInvalidPublicKey, never with a panic or a token BoostX refuses.
func TestUnusableKeys(t *testing.T) {
	zeroD := *generateCurveKey(t, elliptic.P256())
	zeroD.D = big.NewInt(0)
	privateKeys := map[string]*ecdsa.PrivateKey{
		"nil":        nil,
		"zero value": {},
		"P-224":      generateCurveKey(t, elliptic.P224()),
		"P-384":      generateCurveKey(t, elliptic.P384()),
		"P-521":      generateCurveKey(t, elliptic.P521()),
		"D=0":        &zeroD,
	}
	for name, key := range privateKeys {
		if _, err := SignJWT(struct{}{}, key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("SignJWT, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
		if _, err := BuildGID("partner", "user", "bet", key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("BuildGID, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
	}

	privateKey, _ := generateTestKey(t)
	token, _ := SignJWT(struct{}{}, privateKey)
	gid, _ := BuildGID("partner", "user", "bet", privateKey)
	publicKeys := map[string]*ecdsa.PublicKey{
		"nil":        nil,
		"zero value": {},
		"P-384":      &generateCurveKey(t, elliptic.P384()).PublicKey,
	}
	for name, key := range publicKeys {
		var claims struct{}
		if err := ParseJWT(token, &claims, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParseJWT, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
		if err := VerifyGID(gid, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("VerifyGID, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
	}

	if got := VerifyKeysReason(ErrInvalidPublicKey); got != VerifyKeysReasonSignature {
		t.Errorf("VerifyKeysReason(ErrInvalidPublicKey) = %q, want %q", got, VerifyKeysReasonSignature)
	}
}

func TestSignAndParseJWT(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	claims := struct {
		Sub string `json:"sub"`
		RegisteredClaims
	}{
		Sub: "test-subject",
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("SignJWT returned empty token")
	}

	var parsed struct {
		Sub string `json:"sub"`
		RegisteredClaims
	}
	err = ParseJWT(token, &parsed, publicKey)
	if err != nil {
		t.Fatalf("ParseJWT failed: %v", err)
	}

	if parsed.Sub != "test-subject" {
		t.Errorf("expected sub=%q, got %q", "test-subject", parsed.Sub)
	}
}

func TestParseJWT_InvalidSignature(t *testing.T) {
	privateKey, _ := generateTestKey(t)
	_, wrongPublicKey := generateTestKey(t)

	claims := struct {
		Sub string `json:"sub"`
	}{
		Sub: "test-subject",
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	var parsed struct {
		Sub string `json:"sub"`
	}
	err = ParseJWT(token, &parsed, wrongPublicKey)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParseJWT_InvalidFormat(t *testing.T) {
	_, publicKey := generateTestKey(t)

	testCases := []string{
		"",
		"not.a.token",
		"only.two",
		"too.many.parts.here",
	}

	for _, tc := range testCases {
		var parsed struct{}
		err := ParseJWT(tc, &parsed, publicKey)
		if err == nil {
			t.Errorf("expected error for token %q, got nil", tc)
		}
	}
}

func TestExtractJWTClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	claims := struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
	}{
		Partner: "partner-123",
		User:    "user-456",
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	var extracted struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
	}
	err = ExtractJWTClaims(token, &extracted)
	if err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	if extracted.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", extracted.Partner)
	}
	if extracted.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", extracted.User)
	}
}
