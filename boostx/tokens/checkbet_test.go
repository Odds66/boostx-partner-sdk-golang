package tokens

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestParseCheckBetToken(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostxPrivKey, boostxPubKey := generateTestKey(t)

	gid, err := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	if err != nil {
		t.Fatalf("failed to build GID: %v", err)
	}

	claims := checkBetClaims{
		CheckBet: checkBetPayload{
			GID: *gid,
		},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	token, err := SignJWT(claims, boostxPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CheckBet token: %v", err)
	}

	checkBet, err := ParseCheckBetToken(token, boostxPubKey, partnerPubKey)
	if err != nil {
		t.Fatalf("ParseCheckBetToken failed: %v", err)
	}

	if checkBet.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", checkBet.Partner)
	}
	if checkBet.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", checkBet.User)
	}
	if checkBet.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", checkBet.Bet)
	}
}

func TestParseCheckBetToken_NilKeys(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostxPrivKey, boostxPubKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", partnerPrivKey)
	claims := checkBetClaims{
		CheckBet: checkBetPayload{GID: *gid},
	}
	token, _ := SignJWT(claims, boostxPrivKey)

	_, err := ParseCheckBetToken(token, nil, partnerPubKey)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil boostxKey, got %v", err)
	}

	_, err = ParseCheckBetToken(token, boostxPubKey, nil)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey with nil partnerKey, got %v", err)
	}
}

func TestParseCheckBetToken_InvalidSignature(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKey(t)
	boostxPrivKey, _ := generateTestKey(t)
	_, wrongBoostxPubKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", partnerPrivKey)
	claims := checkBetClaims{
		CheckBet: checkBetPayload{GID: *gid},
	}
	token, _ := SignJWT(claims, boostxPrivKey)

	_, err := ParseCheckBetToken(token, wrongBoostxPubKey, partnerPubKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestCheckBetToken_WireFormat(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boostxPrivKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)

	claims := checkBetClaims{
		CheckBet: checkBetPayload{GID: *gid},
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	token, _ := SignJWT(claims, boostxPrivKey)

	var raw map[string]json.RawMessage
	if err := ExtractJWTClaims(token, &raw); err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	if _, ok := raw["checkbet"]; !ok {
		t.Fatal("expected 'checkbet' root key in JWT payload")
	}
	if _, ok := raw["iat"]; !ok {
		t.Fatal("expected 'iat' in JWT payload")
	}

	// Verify no flat legacy fields leak through
	if _, ok := raw["identity"]; ok {
		t.Error("unexpected flat key 'identity' in JWT payload — should be nested under 'checkbet'")
	}
}

func TestExtractCheckBetClaims(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boostxPrivKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	claims := checkBetClaims{
		CheckBet: checkBetPayload{GID: *gid},
	}
	token, _ := SignJWT(claims, boostxPrivKey)

	partner, user, bet, err := ExtractCheckBetClaims(token)
	if err != nil {
		t.Fatalf("ExtractCheckBetClaims failed: %v", err)
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
