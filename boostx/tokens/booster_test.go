package tokens

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCalculateFinalCoefficient(t *testing.T) {
	testCases := []struct {
		x        float64
		boost    float64
		expected float64
	}{
		{2.0, 1.0, 2.0}, // No boost: 1 + (2-1)*1 = 2
		{2.0, 1.5, 2.5}, // 50% boost: 1 + (2-1)*1.5 = 2.5
		{3.0, 2.0, 5.0}, // 100% boost: 1 + (3-1)*2 = 5
		{1.5, 1.0, 1.5}, // No boost on 1.5x
		{1.0, 2.0, 1.0}, // Edge case: x=1 always gives 1
	}

	for _, tc := range testCases {
		result := CalculateFinalCoefficient(tc.x, tc.boost)
		if result != tc.expected {
			t.Errorf("CalculateFinalCoefficient(%v, %v) = %v, want %v", tc.x, tc.boost, result, tc.expected)
		}
	}
}

func TestParseBoosterToken(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boosterPrivKey, boosterPubKey := generateTestKey(t)

	// Build GID
	gid, err := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	if err != nil {
		t.Fatalf("failed to build GID: %v", err)
	}

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:     *gid,
			Round:   1,
			Boost:   1.5,
			Final:   false,
			Jackpot: false,
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	boosterToken, err := SignJWT(bc, boosterPrivKey)
	if err != nil {
		t.Fatalf("failed to sign Booster token: %v", err)
	}

	booster, err := ParseBoosterToken(boosterToken, boosterPubKey, partnerPubKey)
	if err != nil {
		t.Fatalf("ParseBoosterToken failed: %v", err)
	}

	if booster.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", booster.Partner)
	}
	if booster.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", booster.User)
	}
	if booster.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", booster.Bet)
	}
	if booster.Round != 1 {
		t.Errorf("expected round=%d, got %d", 1, booster.Round)
	}
	if booster.Boost != 1.5 {
		t.Errorf("expected boost=%v, got %v", 1.5, booster.Boost)
	}
	if booster.Final != false {
		t.Errorf("expected final=%v, got %v", false, booster.Final)
	}
	if booster.Jackpot != false {
		t.Errorf("expected jackpot=%v, got %v", false, booster.Jackpot)
	}
}

func TestParseBoosterToken_NilPublicKey(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boosterPrivKey, boosterPubKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", partnerPrivKey)

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:   *gid,
			Round: 1,
			Boost: 1.5,
		},
	}

	boosterToken, _ := SignJWT(bc, boosterPrivKey)

	// Test nil boosterPublicKey
	_, err := ParseBoosterToken(boosterToken, nil, partnerPubKey)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil boosterPublicKey, got %v", err)
	}

	// Test nil partnerPublicKey
	_, err = ParseBoosterToken(boosterToken, boosterPubKey, nil)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil partnerPublicKey, got %v", err)
	}
}

func TestParseBoosterToken_InvalidSignature(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boosterPrivKey, _ := generateTestKey(t)
	_, wrongBoosterPubKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", partnerPrivKey)

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:   *gid,
			Round: 1,
			Boost: 1.5,
		},
	}

	boosterToken, _ := SignJWT(bc, boosterPrivKey)

	_, err := ParseBoosterToken(boosterToken, wrongBoosterPubKey, partnerPubKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestExtractBoosterClaims(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boosterPrivKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:   *gid,
			Round: 1,
			Boost: 1.5,
		},
	}

	boosterToken, _ := SignJWT(bc, boosterPrivKey)

	partner, user, bet, err := ExtractBoosterClaims(boosterToken)
	if err != nil {
		t.Fatalf("ExtractBoosterClaims failed: %v", err)
	}

	if partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", partner)
	}
	if user != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", user)
	}
	if bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", bet)
	}
}

func TestBoosterToken_WireFormat(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boosterPrivKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:   *gid,
			Round: 2,
			Boost: 1.3,
			Final: true,
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	token, _ := SignJWT(bc, boosterPrivKey)

	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	if _, ok := raw["booster"]; !ok {
		t.Fatal("expected 'booster' root key in JWT payload")
	}
	if _, ok := raw["iat"]; !ok {
		t.Fatal("expected 'iat' in JWT payload")
	}

	// Verify no flat legacy fields leak through
	for _, key := range []string{"identity", "round", "boost", "final", "jackpot"} {
		if _, ok := raw[key]; ok {
			t.Errorf("unexpected flat key %q in JWT payload — should be nested under 'booster'", key)
		}
	}
}

func TestExtractBoosterClaims_MissingGID(t *testing.T) {
	boosterPrivKey, _ := generateTestKey(t)

	bc := boosterClaims{
		Booster: boosterPayload{
			GID:   GID{}, // Empty GID
			Round: 1,
			Boost: 1.5,
		},
	}

	boosterToken, _ := SignJWT(bc, boosterPrivKey)

	_, _, _, err := ExtractBoosterClaims(boosterToken)
	if !errors.Is(err, ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim, got %v", err)
	}
}
