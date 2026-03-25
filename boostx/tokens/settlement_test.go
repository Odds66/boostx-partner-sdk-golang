package tokens

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestCreateSettlementToken(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateSettlementToken(privateKey, SettlementParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Result:   "won",
		Amount:   150.0,
		Currency: "USD",
	})
	if err != nil {
		t.Fatalf("CreateSettlementToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("CreateSettlementToken returned empty token")
	}

	// Verify wire format by parsing the JWT and checking nested structure
	var claims settlementClaims
	if err := ParseJWT(token, &claims, publicKey); err != nil {
		t.Fatalf("ParseJWT failed: %v", err)
	}

	s := claims.Settlement
	if s.GID.Partner != "partner-123" {
		t.Errorf("expected gid.partner=%q, got %q", "partner-123", s.GID.Partner)
	}
	if s.GID.User != "user-456" {
		t.Errorf("expected gid.user=%q, got %q", "user-456", s.GID.User)
	}
	if s.GID.Bet != "bet-789" {
		t.Errorf("expected gid.bet=%q, got %q", "bet-789", s.GID.Bet)
	}
	if s.GID.Signature == "" {
		t.Error("expected non-empty gid.signature")
	}
	if s.Result != "won" {
		t.Errorf("expected result=%q, got %q", "won", s.Result)
	}
	if s.Payout.Amount != 150.0 {
		t.Errorf("expected payout.amount=%v, got %v", 150.0, s.Payout.Amount)
	}
	if s.Payout.Currency != "USD" {
		t.Errorf("expected payout.currency=%q, got %q", "USD", s.Payout.Currency)
	}

	// Verify GID signature
	if err := VerifyGID(&s.GID, publicKey); err != nil {
		t.Fatalf("GID signature verification failed: %v", err)
	}
}

func TestCreateSettlementToken_WireFormat(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	token, err := CreateSettlementToken(privateKey, SettlementParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Result:   "won",
		Amount:   150.0,
		Currency: "USD",
	})
	if err != nil {
		t.Fatalf("CreateSettlementToken failed: %v", err)
	}

	// Decode raw payload to verify root-level nesting
	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	if _, ok := raw["settlement"]; !ok {
		t.Fatal("expected 'settlement' root key in JWT payload")
	}
	if _, ok := raw["iat"]; !ok {
		t.Fatal("expected 'iat' in JWT payload")
	}
}

func TestCreateSettlementToken_NilPrivateKey(t *testing.T) {
	_, err := CreateSettlementToken(nil, SettlementParams{
		Partner:  "partner",
		User:     "user",
		Bet:      "bet",
		Result:   "won",
		Amount:   100.0,
		Currency: "USD",
	})
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestCreateSettlementToken_MissingClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name   string
		params SettlementParams
	}{
		{"missing partner", SettlementParams{User: "u", Bet: "b", Result: "won", Amount: 0, Currency: "USD"}},
		{"missing user", SettlementParams{Partner: "p", Bet: "b", Result: "won", Amount: 0, Currency: "USD"}},
		{"missing bet", SettlementParams{Partner: "p", User: "u", Result: "won", Amount: 0, Currency: "USD"}},
		{"missing currency", SettlementParams{Partner: "p", User: "u", Bet: "b", Result: "won", Amount: 0}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateSettlementToken(privateKey, tc.params)
			if !errors.Is(err, ErrMissingClaim) {
				t.Errorf("expected ErrMissingClaim, got %v", err)
			}
		})
	}
}

func TestCreateSettlementToken_InvalidResult(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	_, err := CreateSettlementToken(privateKey, SettlementParams{
		Partner:  "partner",
		User:     "user",
		Bet:      "bet",
		Result:   "invalid",
		Amount:   100.0,
		Currency: "USD",
	})
	if !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("expected ErrInvalidClaim, got %v", err)
	}
}

func TestCreateSettlementToken_InvalidAmount(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name   string
		amount float64
	}{
		{"negative", -100.0},
		{"NaN", math.NaN()},
		{"Inf", math.Inf(1)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateSettlementToken(privateKey, SettlementParams{
				Partner:  "partner",
				User:     "user",
				Bet:      "bet",
				Result:   "won",
				Amount:   tc.amount,
				Currency: "USD",
			})
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim, got %v", err)
			}
		})
	}
}

func TestCreateSettlementToken_AllResults(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	for _, result := range []string{"won", "lost", "cancelled", "refunded"} {
		t.Run(result, func(t *testing.T) {
			_, err := CreateSettlementToken(privateKey, SettlementParams{
				Partner:  "partner",
				User:     "user",
				Bet:      "bet",
				Result:   result,
				Amount:   100.0,
				Currency: "USD",
			})
			if err != nil {
				t.Errorf("expected no error for result=%q, got %v", result, err)
			}
		})
	}
}
