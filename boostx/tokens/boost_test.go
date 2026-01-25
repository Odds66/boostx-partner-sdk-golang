package tokens

import (
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

func TestParseBoostToken(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostXPrivKey, boostXPubKey := generateTestKey(t)

	// Create identity sub-token
	identityJWT, err := SignIdentityJWT("partner-123", "user-456", "bet-789", partnerPrivKey)
	if err != nil {
		t.Fatalf("failed to sign identity token: %v", err)
	}

	bc := boostClaims{
		Identity: identityJWT,
		Round:    1,
		Boost:    1.5,
		Final:    false,
		Jackpot:  false,
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	boostToken, err := SignJWT(bc, boostXPrivKey)
	if err != nil {
		t.Fatalf("failed to sign Boost token: %v", err)
	}

	boost, err := ParseBoostToken(boostToken, boostXPubKey, partnerPubKey)
	if err != nil {
		t.Fatalf("ParseBoostToken failed: %v", err)
	}

	if boost.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", boost.Partner)
	}
	if boost.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", boost.User)
	}
	if boost.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", boost.Bet)
	}
	if boost.Round != 1 {
		t.Errorf("expected round=%d, got %d", 1, boost.Round)
	}
	if boost.Boost != 1.5 {
		t.Errorf("expected boost=%v, got %v", 1.5, boost.Boost)
	}
	if boost.Final != false {
		t.Errorf("expected final=%v, got %v", false, boost.Final)
	}
}

func TestParseBoostToken_NilPublicKey(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostXPrivKey, boostXPubKey := generateTestKey(t)

	identityJWT, _ := SignIdentityJWT("partner", "user", "bet", partnerPrivKey)

	bc := boostClaims{
		Identity: identityJWT,
		Round:    1,
		Boost:    1.5,
	}

	boostToken, _ := SignJWT(bc, boostXPrivKey)

	// Test nil boostXPublicKey
	_, err := ParseBoostToken(boostToken, nil, partnerPubKey)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil boostXPublicKey, got %v", err)
	}

	// Test nil partnerPublicKey
	_, err = ParseBoostToken(boostToken, boostXPubKey, nil)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil partnerPublicKey, got %v", err)
	}
}

func TestParseBoostToken_InvalidSignature(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostXPrivKey, _ := generateTestKey(t)
	_, wrongBoostXPubKey := generateTestKey(t)

	identityJWT, _ := SignIdentityJWT("partner", "user", "bet", partnerPrivKey)

	bc := boostClaims{
		Identity: identityJWT,
		Round:    1,
		Boost:    1.5,
	}

	boostToken, _ := SignJWT(bc, boostXPrivKey)

	_, err := ParseBoostToken(boostToken, wrongBoostXPubKey, partnerPubKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestExtractBoostClaims(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boostXPrivKey, _ := generateTestKey(t)

	identityJWT, _ := SignIdentityJWT("partner-123", "user-456", "bet-789", partnerPrivKey)

	bc := boostClaims{
		Identity: identityJWT,
		Round:    1,
		Boost:    1.5,
	}

	boostToken, _ := SignJWT(bc, boostXPrivKey)

	partner, user, bet, err := ExtractBoostClaims(boostToken)
	if err != nil {
		t.Fatalf("ExtractBoostClaims failed: %v", err)
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

func TestExtractBoostClaims_MissingIdentity(t *testing.T) {
	boostXPrivKey, _ := generateTestKey(t)

	bc := boostClaims{
		Identity: "", // Empty
		Round:    1,
		Boost:    1.5,
	}

	boostToken, _ := SignJWT(bc, boostXPrivKey)

	_, _, _, err := ExtractBoostClaims(boostToken)
	if !errors.Is(err, ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim, got %v", err)
	}
}
