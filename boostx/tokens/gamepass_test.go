package tokens

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestCreateGamePassToken(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("CreateGamePassToken returned empty token")
	}

	// Parse and verify
	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}

	if gamePass.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", gamePass.Partner)
	}
	if gamePass.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", gamePass.User)
	}
	if gamePass.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", gamePass.Bet)
	}
	if gamePass.Amount != 100.0 {
		t.Errorf("expected amount=%v, got %v", 100.0, gamePass.Amount)
	}
	if gamePass.Currency != "USD" {
		t.Errorf("expected currency=%q, got %q", "USD", gamePass.Currency)
	}
	if gamePass.X != 2.0 {
		t.Errorf("expected x=%v, got %v", 2.0, gamePass.X)
	}
	if gamePass.XMin != 1.1 {
		t.Errorf("expected xmin=%v, got %v", 1.1, gamePass.XMin)
	}
	if gamePass.XMax != 10.0 {
		t.Errorf("expected xmax=%v, got %v", 10.0, gamePass.XMax)
	}
	if gamePass.Signature == "" {
		t.Error("expected non-empty GID signature")
	}
}

func TestCreateGamePassToken_XDecimals(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:   "partner-123",
		User:      "user-456",
		Bet:       "bet-789",
		Amount:    100.0,
		Currency:  "USD",
		X:         2.0,
		XMin:      1.1,
		XMax:      10.0,
		XDecimals: 4,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}
	if gamePass.XDecimals != 4 {
		t.Errorf("expected xdecimals=%d, got %d", 4, gamePass.XDecimals)
	}

	extracted, err := ExtractGamePassClaims(token)
	if err != nil {
		t.Fatalf("ExtractGamePassClaims failed: %v", err)
	}
	if extracted.XDecimals != 4 {
		t.Errorf("extract: expected xdecimals=%d, got %d", 4, extracted.XDecimals)
	}
}

func TestCreateGamePassToken_XDecimalsDefault(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}
	if gamePass.XDecimals != 0 {
		t.Errorf("expected xdecimals=0 (not set), got %d", gamePass.XDecimals)
	}
}

// TestCreateGamePassToken_XRangeBoundsOnTheWire locks that an unset XMin/XMax
// leaves the key out of xrange (BoostX then applies its defaults) rather than
// sending 0, which BoostX reads as a bound and rejects.
func TestCreateGamePassToken_XRangeBoundsOnTheWire(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	xrange := func(xmin, xmax float64) map[string]any {
		t.Helper()
		token, err := CreateGamePassToken(privateKey, GamePassParams{
			Partner:  "partner-123",
			User:     "user-456",
			Bet:      "bet-789",
			Amount:   100.0,
			Currency: "USD",
			X:        2.0,
			XMin:     xmin,
			XMax:     xmax,
		})
		if err != nil {
			t.Fatalf("CreateGamePassToken failed: %v", err)
		}
		var raw struct {
			GamePass struct {
				XRange map[string]any `json:"xrange"`
			} `json:"gamepass"`
		}
		if err := ExtractJWTClaims(token, &raw); err != nil {
			t.Fatalf("decode raw claims failed: %v", err)
		}
		return raw.GamePass.XRange
	}

	unset := xrange(0, 0)
	for _, key := range []string{"min", "max"} {
		if v, ok := unset[key]; ok {
			t.Errorf("unset bound: expected no %q key, got %v", key, v)
		}
	}

	set := xrange(1.5, 50)
	if set["min"] != 1.5 || set["max"] != 50.0 {
		t.Errorf("set bounds: expected min=1.5 max=50, got min=%v max=%v", set["min"], set["max"])
	}

	onlyMax := xrange(0, 50)
	if _, ok := onlyMax["min"]; ok || onlyMax["max"] != 50.0 {
		t.Errorf("only max set: expected no min and max=50, got %v", onlyMax)
	}
}

func TestCreateGamePassToken_XDecimalsValidation(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	for _, decimals := range []int{1, 7, -1, 100} {
		t.Run(fmt.Sprintf("decimals=%d", decimals), func(t *testing.T) {
			_, err := CreateGamePassToken(privateKey, GamePassParams{
				Partner:   "partner",
				User:      "user",
				Bet:       "bet",
				Amount:    100.0,
				Currency:  "USD",
				X:         2.0,
				XMin:      1.1,
				XMax:      10.0,
				XDecimals: decimals,
			})
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim for decimals=%d, got %v", decimals, err)
			}
		})
	}
}

func TestCreateGamePassToken_XDecimalsValidRange(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	for _, decimals := range []int{2, 3, 4, 5, 6} {
		t.Run(fmt.Sprintf("decimals=%d", decimals), func(t *testing.T) {
			_, err := CreateGamePassToken(privateKey, GamePassParams{
				Partner:   "partner",
				User:      "user",
				Bet:       "bet",
				Amount:    100.0,
				Currency:  "USD",
				X:         2.0,
				XMin:      1.1,
				XMax:      10.0,
				XDecimals: decimals,
			})
			if err != nil {
				t.Errorf("unexpected error for decimals=%d: %v", decimals, err)
			}
		})
	}
}

func TestCreateGamePassToken_EventTitle(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	const eventTitle = "Real Madrid vs Barcelona — Match Winner: Real Madrid"

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:    "partner-123",
		User:       "user-456",
		Bet:        "bet-789",
		Amount:     100.0,
		Currency:   "USD",
		X:          2.0,
		XMin:       1.1,
		XMax:       10.0,
		EventTitle: eventTitle,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}

	if gamePass.EventTitle != eventTitle {
		t.Errorf("expected event_title=%q, got %q", eventTitle, gamePass.EventTitle)
	}

	// Also verify via ExtractGamePassClaims
	extracted, err := ExtractGamePassClaims(token)
	if err != nil {
		t.Fatalf("ExtractGamePassClaims failed: %v", err)
	}
	if extracted.EventTitle != eventTitle {
		t.Errorf("extract: expected event_title=%q, got %q", eventTitle, extracted.EventTitle)
	}
}

func TestCreateGamePassToken_Demo(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
		Demo:     true,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}
	if !gamePass.Demo {
		t.Errorf("expected demo=true, got %v", gamePass.Demo)
	}

	extracted, err := ExtractGamePassClaims(token)
	if err != nil {
		t.Fatalf("ExtractGamePassClaims failed: %v", err)
	}
	if !extracted.Demo {
		t.Errorf("extract: expected demo=true, got %v", extracted.Demo)
	}

	// Wire contract: when demo is set, it must be present on the wire — the
	// backend treats an absent demo as false.
	var raw struct {
		GamePass struct {
			Demo *bool `json:"demo"`
		} `json:"gamepass"`
	}
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("decode raw claims failed: %v", err)
	}
	if raw.GamePass.Demo == nil || !*raw.GamePass.Demo {
		t.Errorf("expected wire demo=true present, got %v", raw.GamePass.Demo)
	}
}

func TestCreateGamePassToken_DemoDefault(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	token, err := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})
	if err != nil {
		t.Fatalf("CreateGamePassToken failed: %v", err)
	}

	gamePass, err := ParseGamePassToken(token, publicKey)
	if err != nil {
		t.Fatalf("ParseGamePassToken failed: %v", err)
	}
	if gamePass.Demo {
		t.Errorf("expected demo=false (unset), got %v", gamePass.Demo)
	}

	// Wire contract: demo is omitted when false — the backend reads an absent
	// demo as false, so the default round-trips without emitting the field.
	var raw struct {
		GamePass map[string]any `json:"gamepass"`
	}
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("decode raw claims failed: %v", err)
	}
	if _, present := raw.GamePass["demo"]; present {
		t.Error("expected demo omitted from wire when false, but it was present")
	}
}

// TestParseGamePassToken_NonBooleanDemoRejected locks the wire contract that a
// non-boolean gamepass.demo is rejected.
// Go's json.Unmarshal into a bool field errors on a string/number, so the demo
// field never silently coerces. (Note: JSON null is the one value Go decodes to
// false rather than rejecting, but the SDK is the signer and omitempty means it
// never emits null — so that divergence is unreachable in practice.)
func TestParseGamePassToken_NonBooleanDemoRejected(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	gid, err := BuildGID("partner", "user", "bet", privateKey)
	if err != nil {
		t.Fatalf("BuildGID failed: %v", err)
	}

	for _, demo := range []any{"yes", "true", float64(1), 0} {
		t.Run(fmt.Sprintf("demo=%v", demo), func(t *testing.T) {
			claims := map[string]any{
				"gamepass": map[string]any{
					"gid":    gid,
					"stake":  map[string]any{"amount": 100.0, "currency": "USD"},
					"xrange": map[string]any{"init": 2.0},
					"demo":   demo,
				},
				"iat": time.Now().Unix(),
			}
			token, err := SignJWT(claims, privateKey)
			if err != nil {
				t.Fatalf("SignJWT failed: %v", err)
			}

			if _, err := ParseGamePassToken(token, publicKey); !errors.Is(err, ErrInvalidGamePass) {
				t.Errorf("ParseGamePassToken: expected ErrInvalidGamePass for demo=%v, got %v", demo, err)
			}
			if _, err := ExtractGamePassClaims(token); !errors.Is(err, ErrInvalidGamePass) {
				t.Errorf("ExtractGamePassClaims: expected ErrInvalidGamePass for demo=%v, got %v", demo, err)
			}
		})
	}
}

func TestCreateGamePassToken_NilPrivateKey(t *testing.T) {
	_, err := CreateGamePassToken(nil, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestCreateGamePassToken_MissingClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name    string
		partner string
		user    string
		bet     string
		wantErr error
	}{
		{"missing partner", "", "user", "bet", ErrMissingClaim},
		{"missing user", "partner", "", "bet", ErrMissingClaim},
		{"missing bet", "partner", "user", "", ErrMissingClaim},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateGamePassToken(privateKey, GamePassParams{
				Partner:  tc.partner,
				User:     tc.user,
				Bet:      tc.bet,
				Amount:   100.0,
				Currency: "USD",
				X:        2.0,
				XMin:     1.1,
				XMax:     10.0,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCreateGamePassToken_InvalidFloatValues(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name   string
		amount float64
		x      float64
		xmin   float64
		xmax   float64
	}{
		{"zero amount", 0, 2.0, 1.1, 10.0},
		{"amount just below 0.01", math.Nextafter(0.01, 0), 2.0, 1.1, 10.0},
		{"tiny amount", 1e-308, 2.0, 1.1, 10.0},
		{"negative amount", -100.0, 2.0, 1.1, 10.0},
		{"zero x", 100.0, 0, 1.1, 10.0},
		{"negative x", 100.0, -2.0, 1.1, 10.0},
		{"negative xmin", 100.0, 2.0, -1.1, 10.0},
		{"negative xmax", 100.0, 2.0, 1.1, -10.0},
		{"NaN amount", math.NaN(), 2.0, 1.1, 10.0},
		{"NaN x", 100.0, math.NaN(), 1.1, 10.0},
		{"Inf amount", math.Inf(1), 2.0, 1.1, 10.0},
		{"Inf x", 100.0, math.Inf(-1), 1.1, 10.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateGamePassToken(privateKey, GamePassParams{
				Partner:  "partner",
				User:     "user",
				Bet:      "bet",
				Amount:   tc.amount,
				Currency: "USD",
				X:        tc.x,
				XMin:     tc.xmin,
				XMax:     tc.xmax,
			})
			if !errors.Is(err, ErrInvalidClaim) {
				t.Errorf("expected ErrInvalidClaim, got %v", err)
			}
		})
	}
}

func TestParseGamePassToken_NilPublicKey(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	token, _ := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner",
		User:     "user",
		Bet:      "bet",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})

	_, err := ParseGamePassToken(token, nil)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestParseGamePassToken_InvalidSignature(t *testing.T) {
	privateKey, _ := generateTestKey(t)
	_, wrongPublicKey := generateTestKey(t)

	token, _ := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner",
		User:     "user",
		Bet:      "bet",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})

	_, err := ParseGamePassToken(token, wrongPublicKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestExtractGamePassClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	token, _ := CreateGamePassToken(privateKey, GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})

	claims, err := ExtractGamePassClaims(token)
	if err != nil {
		t.Fatalf("ExtractGamePassClaims failed: %v", err)
	}

	if claims.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", claims.Partner)
	}
	if claims.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", claims.User)
	}
	if claims.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", claims.Bet)
	}
}

// TestParseGamePassToken_ExactNames pins that the GamePass readers match member
// names exactly, the last repeat winning, so a differently cased member is ignored.
func TestParseGamePassToken_ExactNames(t *testing.T) {
	priv, pub := generateTestKey(t)
	gid, _ := BuildGID("partner", "user", "bet", priv)
	token := func(payload string) string {
		return signRaw(t, priv, `{"alg":"ES256"}`, strings.ReplaceAll(payload, "@gid", gidJSON(gid)))
	}

	got, err := ParseGamePassToken(token(`{"gamepass":{"gid":@gid,"stake":{"amount":5,"AMOUNT":7,"currency":"EUR","currency":"USD"},`+
		`"xrange":{"init":2,"Init":3},"Demo":true},"iat":9,"IAT":10}`), pub)
	if err != nil || got.Amount != 5 || got.Currency != "USD" || got.X != 2 || got.Demo || got.IssuedAt != 9 {
		t.Errorf("expected amount 5 USD, X 2, no demo, iat 9; got %+v, %v", got, err)
	}
	for payload, want := range map[string]error{
		`{"GamePass":{"gid":@gid},"iat":1}`:          ErrMissingClaim,
		`{"gamepass":null,"iat":1}`:                  ErrInvalidClaim,
		`{"gamepass":{"GID":@gid},"iat":1}`:          ErrMissingClaim,
		`{"gamepass":{"gid":{"partner":"partner"}}}`: ErrInvalidGID,
	} {
		if _, err := ParseGamePassToken(token(payload), pub); !errors.Is(err, ErrInvalidGamePass) || !errors.Is(err, want) {
			t.Errorf("%s: expected ErrInvalidGamePass and %v, got %v", payload, want, err)
		}
		if _, err := ExtractGamePassClaims(token(payload)); !errors.Is(err, ErrInvalidGamePass) || !errors.Is(err, want) {
			t.Errorf("extract %s: expected ErrInvalidGamePass and %v, got %v", payload, want, err)
		}
	}
}

// TestCreateGamePassToken_MinimumStake pins that 0.01 is the smallest Amount accepted.
func TestCreateGamePassToken_MinimumStake(t *testing.T) {
	priv, _ := generateTestKey(t)
	for _, amount := range []float64{0.01, math.Nextafter(0.01, 1), 1e308} {
		if _, err := CreateGamePassToken(priv, GamePassParams{Partner: "p", User: "u", Bet: "b", Amount: amount, Currency: "USD", X: 2}); err != nil {
			t.Errorf("amount %v: %v", amount, err)
		}
	}
}

// TestCreateGamePassToken_Currency pins the stake currency rule: 3 or 4
// uppercase ASCII letters, sent unchanged, with no case mapping.
func TestCreateGamePassToken_Currency(t *testing.T) {
	priv, pub := generateTestKey(t)
	params := GamePassParams{Partner: "p", User: "u", Bet: "b", Amount: 1, X: 2}
	for _, currency := range []string{"USD", "USDT", "XAU", "ZZZZ"} {
		params.Currency = currency
		token, err := CreateGamePassToken(priv, params)
		if err != nil {
			t.Errorf("%q: %v", currency, err)
			continue
		}
		if gp, err := ParseGamePassToken(token, pub); err != nil || gp.Currency != currency {
			t.Errorf("%q: expected it sent unchanged, got %+v, %v", currency, gp, err)
		}
	}
	for _, currency := range []string{"usd", "Usd", "usdT", "uſd", "US", "USDTX", "U$D", "US1", " USD", "USD ", "ÜSD", "ＵＳＤ"} {
		params.Currency = currency
		if _, err := CreateGamePassToken(priv, params); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("%q: expected ErrInvalidClaim, got %v", currency, err)
		}
	}
	params.Currency = ""
	if _, err := CreateGamePassToken(priv, params); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("empty currency: expected ErrMissingClaim, got %v", err)
	}
}

// TestCreateGamePassToken_CheckOrder pins that the first failing check is
// reported: ids, currency, amount, x, the xrange options, then the ids'
// UTF-8, so two faults give the error of the first alone.
func TestCreateGamePassToken_CheckOrder(t *testing.T) {
	priv, _ := generateTestKey(t)
	valid := GamePassParams{Partner: "p", User: "u", Bet: "b", Amount: 1, Currency: "USD", X: 2}
	steps := []func(*GamePassParams){
		func(p *GamePassParams) { p.Bet = "" },
		func(p *GamePassParams) { p.Currency = "usd" },
		func(p *GamePassParams) { p.Amount = 0 },
		func(p *GamePassParams) { p.X = 0 },
		func(p *GamePassParams) { p.XDecimals = 9 },
		func(p *GamePassParams) { p.User = string([]byte{0xff}) },
	}
	for i := range len(steps) - 1 {
		first, both := valid, valid
		steps[i](&first)
		steps[i](&both)
		steps[i+1](&both)
		_, want := CreateGamePassToken(priv, first)
		_, got := CreateGamePassToken(priv, both)
		if want == nil || got == nil || got.Error() != want.Error() {
			t.Errorf("faults %d and %d: expected %v, got %v", i, i+1, want, got)
		}
	}
}
