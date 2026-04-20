package tokens

import (
	"errors"
	"math"
	"testing"
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
		{"negative amount", -100.0, 2.0, 1.1, 10.0},
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
