package tokens

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

// validSettlementParams returns params CreateSettlementToken accepts, so tests
// can vary a single field at a time.
func validSettlementParams() SettlementParams {
	return SettlementParams{
		Partner:   "partner-123",
		User:      "user-456",
		Bet:       "bet-789",
		Status:    "win",
		Amount:    150.0,
		Currency:  "USD",
		Version:   1785990000000,
		XSettle:   new(2.5),
		SettledAt: 1785989000000,
	}
}

// settlementObject signs the params and returns the raw JSON of the
// "settlement" payload, so tests can assert on keys that are present or absent
// rather than on Go zero values.
func settlementObject(t *testing.T, params SettlementParams) map[string]json.RawMessage {
	t.Helper()

	privateKey, _ := generateTestKey(t)
	token, err := CreateSettlementToken(privateKey, params)
	if err != nil {
		t.Fatalf("CreateSettlementToken failed: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}
	settlement, ok := raw["settlement"]
	if !ok {
		t.Fatal("expected 'settlement' root key in JWT payload")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(settlement, &fields); err != nil {
		t.Fatalf("unmarshal settlement payload: %v", err)
	}
	return fields
}

func TestCreateSettlementToken(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	params := validSettlementParams()
	token, err := CreateSettlementToken(privateKey, params)
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
	if s.Status != "win" {
		t.Errorf("expected status=%q, got %q", "win", s.Status)
	}
	if s.Payout.Amount != 150.0 {
		t.Errorf("expected payout.amount=%v, got %v", 150.0, s.Payout.Amount)
	}
	if s.Payout.Currency != "USD" {
		t.Errorf("expected payout.currency=%q, got %q", "USD", s.Payout.Currency)
	}
	if s.Version != params.Version {
		t.Errorf("expected version=%d, got %d", params.Version, s.Version)
	}
	if s.XSettle == nil {
		t.Error("expected xSettle to be present")
	} else if *s.XSettle != 2.5 {
		t.Errorf("expected xSettle=%v, got %v", 2.5, *s.XSettle)
	}
	if s.SettledAt != params.SettledAt {
		t.Errorf("expected settledAt=%d, got %d", params.SettledAt, s.SettledAt)
	}

	// Verify GID signature
	if err := VerifyGID(&s.GID, publicKey); err != nil {
		t.Fatalf("GID signature verification failed: %v", err)
	}
}

func TestCreateSettlementToken_WireFormat(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	token, err := CreateSettlementToken(privateKey, validSettlementParams())
	if err != nil {
		t.Fatalf("CreateSettlementToken failed: %v", err)
	}

	// Decode raw payload to verify root-level nesting
	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	settlement, ok := raw["settlement"]
	if !ok {
		t.Fatal("expected 'settlement' root key in JWT payload")
	}
	if _, ok := raw["iat"]; !ok {
		t.Fatal("expected 'iat' in JWT payload")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(settlement, &fields); err != nil {
		t.Fatalf("unmarshal settlement payload: %v", err)
	}
	for key, want := range map[string]string{
		"status":    `"win"`,
		"version":   `1785990000000`,
		"xSettle":   `2.5`,
		"settledAt": `1785989000000`,
	} {
		got, ok := fields[key]
		if !ok {
			t.Errorf("expected %q in the settlement payload", key)
			continue
		}
		if string(got) != want {
			t.Errorf("settlement.%s = %s, want %s", key, got, want)
		}
	}
	for _, key := range []string{"gid", "payout"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("expected %q in the settlement payload", key)
		}
	}
	if _, ok := fields["result"]; ok {
		t.Error("unexpected 'result' in the settlement payload — it was replaced by 'status'")
	}
}

// TestCreateSettlementToken_XSettleOnTheWire covers the field's three states:
// a value, an explicit zero (which must survive as 0, not be dropped), and an
// absent value (which must not appear on the wire at all).
func TestCreateSettlementToken_XSettleOnTheWire(t *testing.T) {
	testCases := []struct {
		name    string
		xSettle *float64
		want    string // raw JSON, or "" when the key must be absent
	}{
		{"supplied", new(2.5), `2.5`},
		{"below one", new(0.5), `0.5`},
		{"zero", new(0.0), `0`},
		{"absent", nil, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			params.XSettle = tc.xSettle
			fields := settlementObject(t, params)

			got, ok := fields["xSettle"]
			if tc.want == "" {
				if ok {
					t.Errorf("expected xSettle to be absent, got %s", got)
				}
				return
			}
			if !ok {
				t.Fatal("expected xSettle in the settlement payload")
			}
			if string(got) != tc.want {
				t.Errorf("xSettle = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestSettlementPayload_XSettleAbsentAndNull confirms an omitted xSettle and an
// explicit null parse to the same thing: nil, meaning "not applicable".
func TestSettlementPayload_XSettleAbsentAndNull(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"absent", `{"gid":{},"status":"cancelled","payout":{"amount":100,"currency":"USD"},"version":1,"settledAt":1785989000000}`},
		{"null", `{"gid":{},"status":"cancelled","payout":{"amount":100,"currency":"USD"},"version":1,"xSettle":null,"settledAt":1785989000000}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var payload settlementPayload
			if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if payload.XSettle != nil {
				t.Errorf("expected xSettle to parse as nil, got %v", *payload.XSettle)
			}
		})
	}
}

func TestCreateSettlementToken_NilPrivateKey(t *testing.T) {
	_, err := CreateSettlementToken(nil, validSettlementParams())
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestCreateSettlementToken_MissingClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name   string
		mutate func(*SettlementParams)
	}{
		{"missing partner", func(p *SettlementParams) { p.Partner = "" }},
		{"missing user", func(p *SettlementParams) { p.User = "" }},
		{"missing bet", func(p *SettlementParams) { p.Bet = "" }},
		{"missing currency", func(p *SettlementParams) { p.Currency = "" }},
		{"missing version", func(p *SettlementParams) { p.Version = 0 }},
		{"missing settledAt", func(p *SettlementParams) { p.SettledAt = 0 }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			tc.mutate(&params)
			_, err := CreateSettlementToken(privateKey, params)
			if !errors.Is(err, ErrMissingClaim) {
				t.Errorf("expected ErrMissingClaim, got %v", err)
			}
		})
	}
}

func TestCreateSettlementToken_AllStatuses(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	statuses := []string{"win", "lose", "cancelled", "refund", "half_win", "half_lose", "cashout", "unsettled"}
	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			params := validSettlementParams()
			params.Status = status
			if status == "unsettled" {
				params.Amount = 0 // an unsettled bet must report a zero payout
			}
			if _, err := CreateSettlementToken(privateKey, params); err != nil {
				t.Errorf("expected no error for status=%q, got %v", status, err)
			}
		})
	}
}

// TestCreateSettlementToken_RejectedStatuses covers the retired values — note
// that "cancelled" survived the rename and is checked as valid above.
func TestCreateSettlementToken_RejectedStatuses(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	rejected := []string{"won", "lost", "refunded", "", "invalid", "WIN", "Win", "half-win", "halfwin"}
	for _, status := range rejected {
		t.Run("status="+status, func(t *testing.T) {
			params := validSettlementParams()
			params.Status = status
			_, err := CreateSettlementToken(privateKey, params)
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim for status=%q, got %v", status, err)
			}
		})
	}
}

func TestCreateSettlementToken_InvalidAmount(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name   string
		status string
		amount float64
	}{
		{"negative", "win", -100.0},
		{"NaN", "win", math.NaN()},
		{"Inf", "win", math.Inf(1)},
		{"unsettled with a payout", "unsettled", 100.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			params.Status = tc.status
			params.Amount = tc.amount
			_, err := CreateSettlementToken(privateKey, params)
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim, got %v", err)
			}
		})
	}
}

func TestCreateSettlementToken_InvalidXSettle(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name    string
		xSettle float64
	}{
		{"negative", -0.5},
		{"NaN", math.NaN()},
		{"+Inf", math.Inf(1)},
		{"-Inf", math.Inf(-1)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			params.XSettle = new(tc.xSettle)
			_, err := CreateSettlementToken(privateKey, params)
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim, got %v", err)
			}
		})
	}
}

func TestCreateSettlementToken_Version(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name    string
		version int64
		wantErr error // nil when the value is accepted
	}{
		{"unset", 0, ErrMissingClaim},
		{"one", 1, nil},
		{"millisecond timestamp", 1785990000000, nil},
		{"largest safe integer", 1<<53 - 1, nil},
		{"negative", -1, ErrInvalidClaim},
		{"beyond the safe integer range", 1 << 53, ErrInvalidClaim},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			params.Version = tc.version
			_, err := CreateSettlementToken(privateKey, params)
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error for version=%d, got %v", tc.version, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v for version=%d, got %v", tc.wantErr, tc.version, err)
			}
		})
	}
}

// TestCreateSettlementToken_CurrencyFormat mirrors the accepted currency shape:
// 3 or 4 uppercase letters.
func TestCreateSettlementToken_CurrencyFormat(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	accepted := []string{"USD", "EUR", "USDT", "XAU"}
	for _, currency := range accepted {
		t.Run("accepts "+currency, func(t *testing.T) {
			params := validSettlementParams()
			params.Currency = currency
			if _, err := CreateSettlementToken(privateKey, params); err != nil {
				t.Errorf("expected no error for currency=%q, got %v", currency, err)
			}
		})
	}

	rejected := []string{"usd", "Usd", "usDT", "US", "DOLLAR", "US1", "US-D", "доллар"}
	for _, currency := range rejected {
		t.Run("rejects "+currency, func(t *testing.T) {
			params := validSettlementParams()
			params.Currency = currency
			_, err := CreateSettlementToken(privateKey, params)
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim for currency=%q, got %v", currency, err)
			}
		})
	}
}

func TestCreateSettlementToken_SettledAtBounds(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	now := time.Now()
	testCases := []struct {
		name      string
		settledAt int64
		wantErr   error // nil when the value is accepted
	}{
		{"unset", 0, ErrMissingClaim},
		{"negative", -1, ErrInvalidClaim},
		{"seconds-scale timestamp", now.Unix(), ErrInvalidClaim},
		{"one below the floor", minSettledAt - 1, ErrInvalidClaim},
		{"at the floor", minSettledAt, nil},
		{"now", now.UnixMilli(), nil},
		{"an hour ago", now.Add(-time.Hour).UnixMilli(), nil},
		{"23 hours ahead", now.Add(23 * time.Hour).UnixMilli(), nil},
		{"25 hours ahead", now.Add(25 * time.Hour).UnixMilli(), ErrInvalidClaim},
		{"a year ahead", now.AddDate(1, 0, 0).UnixMilli(), ErrInvalidClaim},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := validSettlementParams()
			params.SettledAt = tc.settledAt
			_, err := CreateSettlementToken(privateKey, params)
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error for settledAt=%d, got %v", tc.settledAt, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v for settledAt=%d, got %v", tc.wantErr, tc.settledAt, err)
			}
		})
	}
}
