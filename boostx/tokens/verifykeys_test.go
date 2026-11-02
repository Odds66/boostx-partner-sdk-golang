package tokens

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// TestCreateVerifyKeysToken_IllFormedPartnerID: both builders refuse a partner
// id that is not valid UTF-8, after the nonce, instead of signing U+FFFD.
func TestCreateVerifyKeysToken_IllFormedPartnerID(t *testing.T) {
	privKey, _ := generateTestKey(t)
	builders := map[string]func(*ecdsa.PrivateKey, string, int32) (string, error){
		"request":  CreateVerifyKeysRequestToken,
		"response": CreateVerifyKeysResponseToken,
	}
	// A lone high and a lone low surrogate as CESU-8 bytes, and a stray byte.
	for _, id := range []string{"acme\xed\xa0\x80", "acme\xed\xb0\x80", "acme\xff"} {
		for name, create := range builders {
			if _, err := create(privKey, id, 7); !errors.Is(err, ErrInvalidClaim) || !strings.Contains(err.Error(), "partnerID") {
				t.Errorf("%s %q: expected ErrInvalidClaim naming partnerID, got %v", name, id, err)
			}
			if _, err := create(privKey, id, 0); !errors.Is(err, ErrInvalidClaim) || !strings.Contains(err.Error(), "nonce") {
				t.Errorf("%s %q with nonce 0: expected the nonce error first, got %v", name, id, err)
			}
		}
	}
	for name, create := range builders {
		if _, err := create(privKey, "acme\U0001F600", 7); err != nil {
			t.Errorf("%s: a well-formed astral character must sign, got %v", name, err)
		}
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

// TestParseVerifyKeysRequestToken_NilKey pins that both parsers check the key
// before the partner ID.
func TestParseVerifyKeysRequestToken_NilKey(t *testing.T) {
	for _, partnerID := range []string{"partner", "", BoostxIdentity} {
		if _, err := ParseVerifyKeysRequestToken("x.y.z", nil, partnerID, 0); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("request, partner ID %q: expected ErrInvalidPublicKey, got %v", partnerID, err)
		}
		if _, err := ParseVerifyKeysResponseToken("x.y.z", nil, partnerID, 0); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("response, partner ID %q: expected ErrInvalidPublicKey, got %v", partnerID, err)
		}
	}
	_, pub := generateTestKey(t)
	if _, err := ParseVerifyKeysRequestToken("x.y.z", pub, "", 0); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("usable key, empty partner ID: expected ErrMissingClaim, got %v", err)
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

// TestParseVerifyKeysRequestToken_SkewWindow pins the iat window: |now - iat| <=
// maxSkew in whole seconds, with no overflow at the int64 extremes.
func TestParseVerifyKeysRequestToken_SkewWindow(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	parse := func(iat int64, maxSkew time.Duration) error {
		token, err := SignJWT(verifyKeysClaims{
			VerifyKeys:       verifyKeysPayload{Nonce: 1},
			Issuer:           BoostxIdentity,
			Audience:         "partner",
			RegisteredClaims: RegisteredClaims{IssuedAt: iat},
		}, privKey)
		if err != nil {
			t.Fatalf("SignJWT failed: %v", err)
		}
		_, err = ParseVerifyKeysRequestToken(token, pubKey, "partner", maxSkew)
		return err
	}

	for _, tc := range []struct {
		name    string
		offset  int64 // iat - now, in seconds
		maxSkew time.Duration
		stale   bool
	}{
		{"30 s past", -30, 30 * time.Second, false},
		{"30 s ahead", 30, 30 * time.Second, false},
		{"31 s past", -31, 30 * time.Second, true},
		{"31 s ahead", 31, 30 * time.Second, true},
		{"1500 ms window, 1 s past", -1, 1500 * time.Millisecond, false},
		{"1500 ms window, 1 s ahead", 1, 1500 * time.Millisecond, false},
		{"1500 ms window, 2 s past", -2, 1500 * time.Millisecond, true},
		{"1500 ms window, 2 s ahead", 2, 1500 * time.Millisecond, true},
	} {
		for {
			now := time.Now().Unix()
			err := parse(now+tc.offset, tc.maxSkew)
			if time.Now().Unix() != now {
				continue // the second ticked during the parse; try again
			}
			if tc.stale && !errors.Is(err, ErrVerifyKeysStale) {
				t.Errorf("%s: expected ErrVerifyKeysStale, got %v", tc.name, err)
			}
			if !tc.stale && err != nil {
				t.Errorf("%s: expected the token to be accepted, got %v", tc.name, err)
			}
			break
		}
	}

	for _, iat := range []int64{-(1<<53 - 1), 1<<53 - 1} {
		if err := parse(iat, 0); !errors.Is(err, ErrVerifyKeysStale) {
			t.Errorf("iat %d: expected ErrVerifyKeysStale, got %v", iat, err)
		}
	}
	for _, iat := range []int64{math.MinInt64, 1 << 53, math.MaxInt64} {
		if err := parse(iat, 0); !errors.Is(err, ErrVerifyKeysShape) {
			t.Errorf("iat %d: expected ErrVerifyKeysShape, got %v", iat, err)
		}
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

// TestParseVerifyKeysRequestToken_NonceByValue pins that a nonce is judged by
// its value: 5.0 and 5e0 are the nonce 5, while a fraction, a string, a value
// past 2^31-1 or any other JSON type is nonce-format, never shape.
func TestParseVerifyKeysRequestToken_NonceByValue(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	parse := func(nonce string) (*VerifyKeysRequest, error) {
		payload := fmt.Sprintf(`{"verifyKeys":{"nonce":%s},"iss":"boostx","aud":"partner","iat":%d}`, nonce, time.Now().Unix())
		return ParseVerifyKeysRequestToken(signRaw(t, privKey, `{"alg":"ES256"}`, payload), pubKey, "partner", 0)
	}

	for _, nonce := range []string{"5", "5.0", "5e0", "0.5e1"} {
		if got, err := parse(nonce); err != nil || got.Nonce != 5 {
			t.Errorf("nonce %s: expected 5, got %v, %v", nonce, got, err)
		}
	}
	if got, err := parse("2147483647"); err != nil || got.Nonce != 2147483647 {
		t.Errorf("nonce 2^31-1: expected it to be accepted, got %v, %v", got, err)
	}
	for _, nonce := range []string{"3.5", `"42"`, "2147483648", "1e400", "true", "[]", "{}"} {
		if _, err := parse(nonce); !errors.Is(err, ErrVerifyKeysNonce) {
			t.Errorf("nonce %s: expected ErrVerifyKeysNonce, got %v", nonce, err)
		}
	}
}

// TestParseVerifyKeysRequestToken_ClaimTypes pins the claim-type step, all
// shape, and that it reads members by exact name, the last repeat winning.
func TestParseVerifyKeysRequestToken_ClaimTypes(t *testing.T) {
	privKey, pubKey := generateTestKey(t)
	now := time.Now().Unix()
	parse := func(payload string) error {
		_, err := ParseVerifyKeysRequestToken(signRaw(t, privKey, `{"alg":"ES256"}`, payload), pubKey, "partner", 0)
		return err
	}
	vk := `"verifyKeys":{"nonce":1}`

	for name, payload := range map[string]string{
		"iss number":        fmt.Sprintf(`{%s,"iss":1,"aud":"partner","iat":%d}`, vk, now),
		"aud array":         fmt.Sprintf(`{%s,"iss":"boostx","aud":["partner"],"iat":%d}`, vk, now),
		"iat string":        fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":"%d"}`, vk, now),
		"iat fraction":      fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d.5}`, vk, now),
		"verifyKeys string": fmt.Sprintf(`{"verifyKeys":"1","iss":"boostx","aud":"partner","iat":%d}`, now),
		"exp null":          fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"exp":null}`, vk, now),
		"nbf string":        fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"nbf":"0"}`, vk, now),
		"payload null":      `null`,
		"payload array":     `[]`,
		"trailing data":     fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d} {}`, vk, now),
	} {
		if err := parse(payload); !errors.Is(err, ErrVerifyKeysShape) {
			t.Errorf("%s: expected ErrVerifyKeysShape, got %v", name, err)
		}
	}

	for name, payload := range map[string]string{
		"ISS":               fmt.Sprintf(`{%s,"ISS":"boostx","aud":"partner","iat":%d}`, vk, now),
		"repeated iss":      fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"iss":"other"}`, vk, now),
		"null iss and aud":  fmt.Sprintf(`{%s,"iss":null,"aud":null,"iat":%d}`, vk, now),
		"VerifyKeys object": fmt.Sprintf(`{"VerifyKeys":{"nonce":1},"iss":"boostx","aud":"partner","iat":%d}`, now),
	} {
		want := ErrVerifyKeysIssAud
		if name == "VerifyKeys object" {
			want = ErrVerifyKeysNonce
		}
		if err := parse(payload); !errors.Is(err, want) {
			t.Errorf("%s: expected %v, got %v", name, want, err)
		}
	}

	for name, payload := range map[string]string{
		"iat 1e0 form":    fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d.0}`, vk, now),
		"repeated iat":    fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":0,"iat":%d}`, vk, now),
		"exp ahead":       fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"exp":%d}`, vk, now, now+60),
		"nbf behind":      fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"nbf":%d}`, vk, now, now-60),
		"unknown members": fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"jti":null,"Exp":"x"}`, vk, now),
	} {
		if err := parse(payload); err != nil {
			t.Errorf("%s: expected the token to be accepted, got %v", name, err)
		}
	}

	for name, payload := range map[string]string{
		"exp now":    fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"exp":%d}`, vk, now, now-1),
		"nbf ahead":  fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"nbf":%d}`, vk, now, now+60),
		"exp passed": fmt.Sprintf(`{%s,"iss":"boostx","aud":"partner","iat":%d,"exp":1}`, vk, now),
		"no iat":     `{"verifyKeys":{"nonce":1},"iss":"boostx","aud":"partner"}`,
		"iat null":   `{"verifyKeys":{"nonce":1},"iss":"boostx","aud":"partner","iat":null}`,
	} {
		if err := parse(payload); !errors.Is(err, ErrVerifyKeysStale) {
			t.Errorf("%s: expected ErrVerifyKeysStale, got %v", name, err)
		}
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
	// Hand-signed: the create wrapper refuses to mint a "boostx" audience.
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

// TestParseVerifyKeysRequestToken_FormatReasons pins the reason of each format
// fault: the segment count, header and payload are shape; alg, crit and the
// signature segment are signature, and so is a payload changed after signing,
// since the signature covers the payload text before it is decoded.
func TestParseVerifyKeysRequestToken_FormatReasons(t *testing.T) {
	key, pub := generateTestKey(t)
	payload := fmt.Sprintf(`{"verifyKeys":{"nonce":1},"iss":"boostx","aud":"partner","iat":%d}`, time.Now().Unix())
	alg := `{"alg":"ES256"}`
	token := signRaw(t, key, alg, payload)
	parts := strings.Split(token, ".")
	signSegments := func(h, p string) string { // signs the segment text exactly as given
		sig, err := signES256(key, []byte(h+"."+p))
		if err != nil {
			t.Fatal(err)
		}
		return h + "." + p + "." + base64URLEncode(sig)
	}
	spaced := func(seg string) string { return seg[:4] + " " + seg[4:] }

	for name, tc := range map[string]struct{ token, want string }{
		"canonical":               {token, ""},
		"other header members":    {signRaw(t, key, `{"typ":1,"kid":{},"alg":"ES256","x5u":null}`, payload), ""},
		"whitespace around JSON":  {signRaw(t, key, " "+alg+"\n", "\t"+payload+" "), ""},
		"two segments":            {parts[0] + "." + parts[1], VerifyKeysReasonShape},
		"four segments":           {token + ".", VerifyKeysReasonShape},
		"header null":             {signRaw(t, key, `null`, payload), VerifyKeysReasonShape},
		"header array":            {signRaw(t, key, `[]`, payload), VerifyKeysReasonShape},
		"header invalid UTF-8":    {signRaw(t, key, "{\"alg\":\"ES256\",\"kid\":\"\xff\"}", payload), VerifyKeysReasonShape},
		"header byte order mark":  {signRaw(t, key, "\xef\xbb\xbf"+alg, payload), VerifyKeysReasonShape},
		"header padded":           {signSegments(parts[0]+"==", parts[1]), VerifyKeysReasonShape},
		"header with a space":     {signSegments(spaced(parts[0]), parts[1]), VerifyKeysReasonShape},
		"leading space":           {" " + token, VerifyKeysReasonShape},
		"alg absent":              {signRaw(t, key, `{}`, payload), VerifyKeysReasonSignature},
		"ALG":                     {signRaw(t, key, `{"ALG":"ES256"}`, payload), VerifyKeysReasonSignature},
		"alg lower case":          {signRaw(t, key, `{"alg":"es256"}`, payload), VerifyKeysReasonSignature},
		"alg null":                {signRaw(t, key, `{"alg":null}`, payload), VerifyKeysReasonSignature},
		"alg array":               {signRaw(t, key, `{"alg":["ES256"]}`, payload), VerifyKeysReasonSignature},
		"crit empty":              {signRaw(t, key, `{"alg":"ES256","crit":[]}`, payload), VerifyKeysReasonSignature},
		"crit null":               {signRaw(t, key, `{"alg":"ES256","crit":null}`, payload), VerifyKeysReasonSignature},
		"trailing newline":        {token + "\n", VerifyKeysReasonSignature},
		"signature padded":        {token + "==", VerifyKeysReasonSignature},
		"63-byte signature":       {parts[0] + "." + parts[1] + "." + base64URLEncode(make([]byte, 63)), VerifyKeysReasonSignature},
		"payload changed":         {parts[0] + "." + spaced(parts[1]) + "." + parts[2], VerifyKeysReasonSignature},
		"payload with a space":    {signSegments(parts[0], spaced(parts[1])), VerifyKeysReasonShape},
		"payload padded":          {signSegments(parts[0], parts[1]+"=="), VerifyKeysReasonShape},
		"payload invalid UTF-8":   {signRaw(t, key, alg, "{\"x\":\"\xc0\xaf\"}"), VerifyKeysReasonShape},
		"payload byte order mark": {signRaw(t, key, alg, "\xef\xbb\xbf"+payload), VerifyKeysReasonShape},
		"payload trailing data":   {signRaw(t, key, alg, payload+"{}"), VerifyKeysReasonShape},
		"payload string":          {signRaw(t, key, alg, `"x"`), VerifyKeysReasonShape},
	} {
		got := ""
		if _, err := ParseVerifyKeysRequestToken(tc.token, pub, "partner", 0); err != nil {
			got = VerifyKeysReason(err)
		}
		if got != tc.want {
			t.Errorf("%s: got reason %q, want %q", name, got, tc.want)
		}
	}
}

// TestParseVerifyKeysRequestToken_CheckOrder pins that the first failing
// check decides the reason: format and signature, claim types (shape),
// iss and aud, the time window and exp/nbf (stale), then the nonce.
func TestParseVerifyKeysRequestToken_CheckOrder(t *testing.T) {
	key, pub := generateTestKey(t)
	now := time.Now().Unix()
	for name, tc := range map[string]struct{ header, payload, want string }{
		"crit before a null payload":   {`{"alg":"ES256","crit":["exp"]}`, `null`, VerifyKeysReasonSignature},
		"iat type before iss and aud":  {`{"alg":"ES256"}`, `{"iss":"x","aud":"y","iat":"1","verifyKeys":{"nonce":0}}`, VerifyKeysReasonShape},
		"iat 1e400 before iss and aud": {`{"alg":"ES256"}`, `{"iss":"x","aud":"y","iat":1e400}`, VerifyKeysReasonShape},
		"exp null before iss and aud":  {`{"alg":"ES256"}`, `{"iss":"x","aud":"y","iat":1,"exp":null}`, VerifyKeysReasonShape},
		"verifyKeys type before stale": {`{"alg":"ES256"}`, `{"iss":"boostx","aud":"partner","iat":1,"verifyKeys":[1]}`, VerifyKeysReasonShape},
		"iss and aud before stale":     {`{"alg":"ES256"}`, `{"iss":"x","aud":"partner","iat":1,"verifyKeys":{"nonce":0}}`, VerifyKeysReasonIssAud},
		"stale before the nonce":       {`{"alg":"ES256"}`, `{"iss":"boostx","aud":"partner","iat":1,"verifyKeys":{"nonce":"x"}}`, VerifyKeysReasonStale},
		"exp before the nonce": {`{"alg":"ES256"}`,
			fmt.Sprintf(`{"iss":"boostx","aud":"partner","iat":%d,"exp":1,"verifyKeys":{"nonce":0}}`, now), VerifyKeysReasonStale},
		"nonce last": {`{"alg":"ES256"}`,
			fmt.Sprintf(`{"iss":"boostx","aud":"partner","iat":%de0,"verifyKeys":{"nonce":0}}`, now), VerifyKeysReasonNonceFormat},
	} {
		_, err := ParseVerifyKeysRequestToken(signRaw(t, key, tc.header, tc.payload), pub, "partner", 0)
		if err == nil || VerifyKeysReason(err) != tc.want {
			t.Errorf("%s: got %v, want reason %q", name, err, tc.want)
		}
	}
}

// TestParseVerifyKeysRequestToken_ExpNbfAtNow pins the boundary in whole
// seconds with no leeway: exp must be after now, and nbf may equal now.
func TestParseVerifyKeysRequestToken_ExpNbfAtNow(t *testing.T) {
	key, pub := generateTestKey(t)
	for _, tc := range []struct {
		claim  string
		offset int64 // claim - now, in seconds
		stale  bool
	}{
		{"exp", 0, true},
		{"exp", 1, false},
		{"nbf", 0, false},
		{"nbf", 1, true},
	} {
		for {
			now := time.Now().Unix()
			payload := fmt.Sprintf(`{"verifyKeys":{"nonce":1},"iss":"boostx","aud":"partner","iat":%d,%q:%d}`, now, tc.claim, now+tc.offset)
			_, err := ParseVerifyKeysRequestToken(signRaw(t, key, `{"alg":"ES256"}`, payload), pub, "partner", 0)
			if time.Now().Unix() != now {
				continue // the second ticked during the parse; try again
			}
			if stale := errors.Is(err, ErrVerifyKeysStale); stale != tc.stale || !stale && err != nil {
				t.Errorf("%s now%+d: got %v, want stale %t", tc.claim, tc.offset, err, tc.stale)
			} else if stale && (!strings.Contains(err.Error(), tc.claim+" is") || strings.Contains(err.Error(), "iat")) {
				t.Errorf("%s now%+d: the error %q does not name %s", tc.claim, tc.offset, err, tc.claim)
			}
			break
		}
	}
}
