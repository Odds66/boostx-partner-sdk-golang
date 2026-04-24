package tokens

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestVerifyKeysErrors_WrapInvalidVerifyKeys(t *testing.T) {
	// Every reason-specific sentinel must chain through ErrInvalidVerifyKeys
	// so callers can write a single check to catch any VerifyKeys failure.
	for _, err := range []error{
		ErrVerifyKeysShape,
		ErrVerifyKeysIssAud,
		ErrVerifyKeysStale,
		ErrVerifyKeysNonce,
	} {
		if !errors.Is(err, ErrInvalidVerifyKeys) {
			t.Errorf("%v does not wrap ErrInvalidVerifyKeys", err)
		}
	}
}

func TestCreateVerifyKeysToken_RoundTrip(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	const nonce int32 = 12345

	token, err := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner-123", nonce)
	if err != nil {
		t.Fatalf("CreateVerifyKeysToken failed: %v", err)
	}

	vk, err := ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "partner-123", 0)
	if err != nil {
		t.Fatalf("ParseVerifyKeysToken failed: %v", err)
	}
	if vk.Issuer != BoostxIdentity {
		t.Errorf("expected iss=%q, got %q", BoostxIdentity, vk.Issuer)
	}
	if vk.Audience != "partner-123" {
		t.Errorf("expected aud=%q, got %q", "partner-123", vk.Audience)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected nonce=%d, got %d", nonce, vk.Nonce)
	}
}

func TestCreateVerifyKeysToken_ErrorCases(t *testing.T) {
	privKey, _ := generateTestKey(t)

	if _, err := CreateVerifyKeysToken(nil, BoostxIdentity, "partner", 1); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("nil key: expected ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := CreateVerifyKeysToken(privKey, "", "partner", 1); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("empty iss: expected ErrMissingClaim, got %v", err)
	}
	if _, err := CreateVerifyKeysToken(privKey, BoostxIdentity, "", 1); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("empty aud: expected ErrMissingClaim, got %v", err)
	}
	if _, err := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner", 0); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("zero nonce: expected ErrInvalidClaim, got %v", err)
	}
	if _, err := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner", -1); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("negative nonce: expected ErrInvalidClaim, got %v", err)
	}
}

func TestParseVerifyKeysToken_NilKey(t *testing.T) {
	_, err := ParseVerifyKeysToken("x.y.z", nil, BoostxIdentity, "partner", 0)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestParseVerifyKeysToken_WrongSignature(t *testing.T) {
	privKey, _ := generateTestKey(t)
	_, wrongPubKey := generateTestKey(t)

	token, _ := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner", 42)
	_, err := ParseVerifyKeysToken(token, wrongPubKey, BoostxIdentity, "partner", 0)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParseVerifyKeysToken_IssAudMismatch(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	token, _ := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner-123", 42)

	_, err := ParseVerifyKeysToken(token, pubKey, "not-boostx", "partner-123", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("iss mismatch: expected ErrVerifyKeysIssAud, got %v", err)
	}

	_, err = ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "wrong-partner", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("aud mismatch: expected ErrVerifyKeysIssAud, got %v", err)
	}
}

func TestParseVerifyKeysToken_Stale(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	claims := verifyKeysClaims{
		VerifyKeys:       verifyKeysPayload{Nonce: 1},
		Issuer:           BoostxIdentity,
		Audience:         "partner",
		RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Add(-2 * time.Minute).Unix()},
	}
	token, err := SignJWT(claims, privKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	_, err = ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "partner", 30*time.Second)
	if !errors.Is(err, ErrVerifyKeysStale) {
		t.Errorf("expected ErrVerifyKeysStale, got %v", err)
	}
}

// TestParseVerifyKeysToken_NonceFormat covers the three ways a nonce can be
// rejected as nonce-format without a JSON-level error: zero, negative, and
// missing (absent verifyKeys object / absent nonce key / explicit null —
// all unmarshal to Nonce=0).
func TestParseVerifyKeysToken_NonceFormat(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	cases := []struct {
		name   string
		claims any
	}{
		{
			name: "zero nonce",
			claims: verifyKeysClaims{
				VerifyKeys:       verifyKeysPayload{Nonce: 0},
				Issuer:           BoostxIdentity,
				Audience:         "partner",
				RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Unix()},
			},
		},
		{
			name: "negative nonce",
			claims: verifyKeysClaims{
				VerifyKeys:       verifyKeysPayload{Nonce: -5},
				Issuer:           BoostxIdentity,
				Audience:         "partner",
				RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Unix()},
			},
		},
		{
			name: "missing verifyKeys object",
			claims: map[string]any{
				"iss": BoostxIdentity,
				"aud": "partner",
				"iat": time.Now().Unix(),
			},
		},
		{
			name: "null nonce",
			claims: map[string]any{
				"verifyKeys": map[string]any{"nonce": nil},
				"iss":        BoostxIdentity,
				"aud":        "partner",
				"iat":        time.Now().Unix(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := SignJWT(tc.claims, privKey)
			if err != nil {
				t.Fatalf("SignJWT failed: %v", err)
			}
			_, err = ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "partner", 0)
			if !errors.Is(err, ErrVerifyKeysNonce) {
				t.Errorf("expected ErrVerifyKeysNonce, got %v", err)
			}
		})
	}
}

// TestParseVerifyKeysToken_ShapeFromUnmarshalFailure covers the wire-level
// malformations that fail JSON unmarshal into the claims struct (non-integer
// nonce, string nonce, int32 overflow). These surface as ErrVerifyKeysShape.
func TestParseVerifyKeysToken_ShapeFromUnmarshalFailure(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	cases := []struct {
		name  string
		nonce any
	}{
		{"float nonce", 3.5},
		{"string nonce", "42"},
		{"overflow nonce", int64(2147483648)}, // 2^31, one past int32 max
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{
				"verifyKeys": map[string]any{"nonce": tc.nonce},
				"iss":        BoostxIdentity,
				"aud":        "partner",
				"iat":        time.Now().Unix(),
			}
			token, err := SignJWT(claims, privKey)
			if err != nil {
				t.Fatalf("SignJWT failed: %v", err)
			}
			_, err = ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "partner", 0)
			if !errors.Is(err, ErrVerifyKeysShape) {
				t.Errorf("expected ErrVerifyKeysShape, got %v", err)
			}
		})
	}
}

func TestParseVerifyKeysToken_NegativeSkew(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	token, _ := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner", 1)

	_, err := ParseVerifyKeysToken(token, pubKey, BoostxIdentity, "partner", -1*time.Second)
	if !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("expected ErrInvalidClaim for negative maxSkew, got %v", err)
	}
}

func TestExtractVerifyKeysAudience(t *testing.T) {
	privKey, _ := generateTestKey(t)
	token, _ := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner-xyz", 99)

	aud, err := ExtractVerifyKeysAudience(token)
	if err != nil {
		t.Fatalf("ExtractVerifyKeysAudience failed: %v", err)
	}
	if aud != "partner-xyz" {
		t.Errorf("expected aud=%q, got %q", "partner-xyz", aud)
	}
}

func TestVerifyKeysToken_WireFormat(t *testing.T) {
	privKey, _ := generateTestKey(t)
	token, _ := CreateVerifyKeysToken(privKey, BoostxIdentity, "partner-123", 7)

	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	for _, k := range []string{"verifyKeys", "iss", "aud", "iat"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("expected root key %q in payload", k)
		}
	}

	var inner struct {
		Nonce int32 `json:"nonce"`
	}
	if err := json.Unmarshal(raw["verifyKeys"], &inner); err != nil {
		t.Fatalf("failed to unmarshal verifyKeys: %v", err)
	}
	if inner.Nonce != 7 {
		t.Errorf("expected nested nonce=7, got %d", inner.Nonce)
	}
}
