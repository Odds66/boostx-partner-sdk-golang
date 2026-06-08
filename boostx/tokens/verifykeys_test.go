package tokens

import (
	"encoding/json"
	"errors"
	"strings"
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

func TestCreateVerifyKeysRequestToken_RoundTrip(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	const nonce int32 = 12345

	token, err := CreateVerifyKeysRequestToken(privKey, "partner-123", nonce)
	if err != nil {
		t.Fatalf("CreateVerifyKeysRequestToken failed: %v", err)
	}

	vk, err := ParseVerifyKeysRequestToken(token, pubKey, "partner-123", 0)
	if err != nil {
		t.Fatalf("ParseVerifyKeysRequestToken failed: %v", err)
	}
	if vk.PartnerID != "partner-123" {
		t.Errorf("expected partnerID=%q, got %q", "partner-123", vk.PartnerID)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected nonce=%d, got %d", nonce, vk.Nonce)
	}
}

// TestCreateVerifyKeysResponseToken_RoundTrip proves the response wrappers fix
// iss/aud the opposite way round: iss=partnerID, aud="boostx".
func TestCreateVerifyKeysResponseToken_RoundTrip(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	const nonce int32 = 54321

	token, err := CreateVerifyKeysResponseToken(privKey, "partner-123", nonce)
	if err != nil {
		t.Fatalf("CreateVerifyKeysResponseToken failed: %v", err)
	}

	vk, err := ParseVerifyKeysResponseToken(token, pubKey, "partner-123", 0)
	if err != nil {
		t.Fatalf("ParseVerifyKeysResponseToken failed: %v", err)
	}
	if vk.PartnerID != "partner-123" {
		t.Errorf("expected partnerID=%q, got %q", "partner-123", vk.PartnerID)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected nonce=%d, got %d", nonce, vk.Nonce)
	}
}

func TestCreateVerifyKeysRequestToken_ErrorCases(t *testing.T) {
	privKey, _ := generateTestKey(t)

	if _, err := CreateVerifyKeysRequestToken(nil, "partner", 1); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("nil key: expected ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := CreateVerifyKeysRequestToken(privKey, "", 1); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("empty partnerID: expected ErrMissingClaim, got %v", err)
	} else if !strings.Contains(err.Error(), "partnerID") {
		t.Errorf("empty partnerID: error should name partnerID, got %q", err)
	}
	if _, err := CreateVerifyKeysRequestToken(privKey, BoostxIdentity, 1); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("boostx partnerID: expected ErrInvalidClaim, got %v", err)
	} else if !strings.Contains(err.Error(), "partnerID") {
		t.Errorf("boostx partnerID: error should name partnerID, got %q", err)
	}
	if _, err := CreateVerifyKeysRequestToken(privKey, "partner", 0); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("zero nonce: expected ErrInvalidClaim, got %v", err)
	}
	if _, err := CreateVerifyKeysRequestToken(privKey, "partner", -1); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("negative nonce: expected ErrInvalidClaim, got %v", err)
	}
}

func TestCreateVerifyKeysResponseToken_ErrorCases(t *testing.T) {
	privKey, _ := generateTestKey(t)

	if _, err := CreateVerifyKeysResponseToken(nil, "partner", 1); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("nil key: expected ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := CreateVerifyKeysResponseToken(privKey, "", 1); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("empty partnerID: expected ErrMissingClaim, got %v", err)
	} else if !strings.Contains(err.Error(), "partnerID") {
		t.Errorf("empty partnerID: error should name partnerID, got %q", err)
	}
	if _, err := CreateVerifyKeysResponseToken(privKey, BoostxIdentity, 1); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("boostx partnerID: expected ErrInvalidClaim, got %v", err)
	} else if !strings.Contains(err.Error(), "partnerID") {
		t.Errorf("boostx partnerID: error should name partnerID, got %q", err)
	}
}

// TestParseVerifyKeysToken_RejectsBoostxPartnerID covers the parse-side guard:
// "boostx" is never a valid partnerID, so both directions reject it before
// touching the token (a partner named "boostx" would make request and response
// claims indistinguishable).
func TestParseVerifyKeysToken_RejectsBoostxPartnerID(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	token, _ := CreateVerifyKeysResponseToken(privKey, "partner-123", 1)

	if _, err := ParseVerifyKeysRequestToken(token, pubKey, BoostxIdentity, 0); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("request: expected ErrInvalidClaim, got %v", err)
	}
	if _, err := ParseVerifyKeysResponseToken(token, pubKey, BoostxIdentity, 0); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("response: expected ErrInvalidClaim, got %v", err)
	}
}

func TestParseVerifyKeysRequestToken_NilKey(t *testing.T) {
	_, err := ParseVerifyKeysRequestToken("x.y.z", nil, "partner", 0)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestParseVerifyKeysRequestToken_WrongSignature(t *testing.T) {
	privKey, _ := generateTestKey(t)
	_, wrongPubKey := generateTestKey(t)

	token, _ := CreateVerifyKeysRequestToken(privKey, "partner", 42)
	_, err := ParseVerifyKeysRequestToken(token, wrongPubKey, "partner", 0)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParseVerifyKeysRequestToken_IssAudMismatch(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	// iss is baked into the request creator, so a wrong-iss token must be
	// hand-signed to exercise the issuer check.
	wrongIss := verifyKeysClaims{
		VerifyKeys:       verifyKeysPayload{Nonce: 42},
		Issuer:           "not-boostx",
		Audience:         "partner-123",
		RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Unix()},
	}
	token, err := SignJWT(wrongIss, privKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}
	_, err = ParseVerifyKeysRequestToken(token, pubKey, "partner-123", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("iss mismatch: expected ErrVerifyKeysIssAud, got %v", err)
	}

	token, _ = CreateVerifyKeysRequestToken(privKey, "partner-123", 42)
	_, err = ParseVerifyKeysRequestToken(token, pubKey, "wrong-partner", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("aud mismatch: expected ErrVerifyKeysIssAud, got %v", err)
	}
}

// TestParseVerifyKeysResponseToken_IssAudMismatch covers the response
// direction: a request token (iss=boostx) must not parse as a response, and a
// response for one partner must not parse for another.
func TestParseVerifyKeysResponseToken_IssAudMismatch(t *testing.T) {
	privKey, pubKey := generateTestKey(t)

	token, _ := CreateVerifyKeysRequestToken(privKey, "partner-123", 42)
	_, err := ParseVerifyKeysResponseToken(token, pubKey, "partner-123", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("request-as-response: expected ErrVerifyKeysIssAud, got %v", err)
	}

	token, _ = CreateVerifyKeysResponseToken(privKey, "partner-123", 42)
	_, err = ParseVerifyKeysResponseToken(token, pubKey, "wrong-partner", 0)
	if !errors.Is(err, ErrVerifyKeysIssAud) {
		t.Errorf("wrong partner: expected ErrVerifyKeysIssAud, got %v", err)
	}
}

func TestParseVerifyKeysRequestToken_Stale(t *testing.T) {
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

	_, err = ParseVerifyKeysRequestToken(token, pubKey, "partner", 30*time.Second)
	if !errors.Is(err, ErrVerifyKeysStale) {
		t.Errorf("expected ErrVerifyKeysStale, got %v", err)
	}
}

// TestParseVerifyKeysRequestToken_NonceFormat covers the three ways a nonce can
// be rejected as nonce-format without a JSON-level error: zero, negative, and
// missing (absent verifyKeys object / absent nonce key / explicit null —
// all unmarshal to Nonce=0). Both directions funnel through the same shared
// helper, so the matrix runs on the request path only.
func TestParseVerifyKeysRequestToken_NonceFormat(t *testing.T) {
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
			_, err = ParseVerifyKeysRequestToken(token, pubKey, "partner", 0)
			if !errors.Is(err, ErrVerifyKeysNonce) {
				t.Errorf("expected ErrVerifyKeysNonce, got %v", err)
			}
		})
	}
}

// TestParseVerifyKeysRequestToken_ShapeFromUnmarshalFailure covers the
// wire-level malformations that fail JSON unmarshal into the claims struct
// (non-integer nonce, string nonce, int32 overflow). These surface as
// ErrVerifyKeysShape.
func TestParseVerifyKeysRequestToken_ShapeFromUnmarshalFailure(t *testing.T) {
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
			_, err = ParseVerifyKeysRequestToken(token, pubKey, "partner", 0)
			if !errors.Is(err, ErrVerifyKeysShape) {
				t.Errorf("expected ErrVerifyKeysShape, got %v", err)
			}
		})
	}
}

func TestParseVerifyKeysRequestToken_NegativeSkew(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	token, _ := CreateVerifyKeysRequestToken(privKey, "partner", 1)

	_, err := ParseVerifyKeysRequestToken(token, pubKey, "partner", -1*time.Second)
	if !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("expected ErrInvalidClaim for negative maxSkew, got %v", err)
	}
}

func TestExtractVerifyKeysRequestPartner(t *testing.T) {
	privKey, _ := generateTestKey(t)
	token, _ := CreateVerifyKeysRequestToken(privKey, "partner-xyz", 99)

	partner, err := ExtractVerifyKeysRequestPartner(token)
	if err != nil {
		t.Fatalf("ExtractVerifyKeysRequestPartner failed: %v", err)
	}
	if partner != "partner-xyz" {
		t.Errorf("expected partner=%q, got %q", "partner-xyz", partner)
	}
}

// TestExtractVerifyKeysRequestPartner_RejectsBoostxAudience verifies the
// untrusted-input guard: a request claiming aud="boostx" is malformed (no real
// partner is the BoostX identity) and is rejected before any key lookup.
func TestExtractVerifyKeysRequestPartner_RejectsBoostxAudience(t *testing.T) {
	privKey, _ := generateTestKey(t)
	// Hand-signed: the create wrapper now refuses to mint a "boostx" audience.
	claims := verifyKeysClaims{
		VerifyKeys:       verifyKeysPayload{Nonce: 1},
		Issuer:           BoostxIdentity,
		Audience:         BoostxIdentity,
		RegisteredClaims: RegisteredClaims{IssuedAt: time.Now().Unix()},
	}
	token, err := SignJWT(claims, privKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}
	if _, err := ExtractVerifyKeysRequestPartner(token); !errors.Is(err, ErrVerifyKeysShape) {
		t.Errorf("expected ErrVerifyKeysShape, got %v", err)
	}
}

// TestVerifyKeysToken_WireFormat pins the payload shape and asserts each
// direction writes iss/aud into the correct slots on the wire.
func TestVerifyKeysToken_WireFormat(t *testing.T) {
	privKey, _ := generateTestKey(t)

	cases := []struct {
		name    string
		token   func() (string, error)
		wantIss string
		wantAud string
	}{
		{
			name:    "request",
			token:   func() (string, error) { return CreateVerifyKeysRequestToken(privKey, "partner-123", 7) },
			wantIss: BoostxIdentity,
			wantAud: "partner-123",
		},
		{
			name:    "response",
			token:   func() (string, error) { return CreateVerifyKeysResponseToken(privKey, "partner-123", 7) },
			wantIss: "partner-123",
			wantAud: BoostxIdentity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.token()
			if err != nil {
				t.Fatalf("create token failed: %v", err)
			}

			var raw map[string]json.RawMessage
			if err := ExtractJWTClaims(token, &raw); err != nil {
				t.Fatalf("ExtractJWTClaims failed: %v", err)
			}

			for _, k := range []string{"verifyKeys", "iss", "aud", "iat"} {
				if _, ok := raw[k]; !ok {
					t.Errorf("expected root key %q in payload", k)
				}
			}

			var iss, aud string
			if err := json.Unmarshal(raw["iss"], &iss); err != nil {
				t.Fatalf("failed to unmarshal iss: %v", err)
			}
			if err := json.Unmarshal(raw["aud"], &aud); err != nil {
				t.Fatalf("failed to unmarshal aud: %v", err)
			}
			if iss != tc.wantIss {
				t.Errorf("expected iss=%q, got %q", tc.wantIss, iss)
			}
			if aud != tc.wantAud {
				t.Errorf("expected aud=%q, got %q", tc.wantAud, aud)
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
		})
	}
}
