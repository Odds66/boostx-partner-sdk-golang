package tokens

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestInboundRefusals pins that every refusal of an inbound token matches its
// token error and its cause, while a nil key is ErrInvalidPublicKey alone.
func TestInboundRefusals(t *testing.T) {
	partnerPriv, partnerPub := generateTestKey(t)
	boostxPriv, boostxPub := generateTestKey(t)
	otherPriv, _ := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", partnerPriv)
	foreignGID, _ := BuildGID("partner", "user", "bet", otherPriv)

	sign := func(claims any, key *ecdsa.PrivateKey) string {
		token, err := SignJWT(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	// algNone swaps the header for one naming another algorithm.
	algNone := func(token string) string {
		return base64URLEncode([]byte(`{"alg":"none","typ":"JWT"}`)) + token[strings.Index(token, "."):]
	}
	booster := func(g GID, key *ecdsa.PrivateKey) string {
		return sign(boosterClaims{Booster: boosterPayload{GID: g, Round: 1, Boost: 1.5}}, key)
	}
	checkBet := func(g GID, key *ecdsa.PrivateKey) string {
		return sign(checkBetClaims{CheckBet: checkBetPayload{GID: g}}, key)
	}
	gamePass := func(g GID, key *ecdsa.PrivateKey) string {
		return sign(gamePassClaims{GamePass: gamePassPayload{GID: g}}, key)
	}
	verifyKeys, _ := CreateVerifyKeysRequestToken(boostxPriv, "partner", 1)

	parseBooster := func(token string, boostxKey, partnerKey *ecdsa.PublicKey) error {
		_, err := ParseBoosterToken(token, boostxKey, partnerKey)
		return err
	}
	parseCheckBet := func(token string, boostxKey, partnerKey *ecdsa.PublicKey) error {
		_, err := ParseCheckBetToken(token, boostxKey, partnerKey)
		return err
	}
	parseGamePass := func(token string, key *ecdsa.PublicKey) error {
		_, err := ParseGamePassToken(token, key)
		return err
	}
	parseVerifyKeys := func(token string, key *ecdsa.PublicKey) error {
		_, err := ParseVerifyKeysRequestToken(token, key, "partner", time.Minute)
		return err
	}
	extract := func(_ string, err error) error { return err }
	extractGamePass := func(_ *GamePass, err error) error { return err }

	tests := []struct {
		name string
		err  error
		want []error // every one must match
		not  error   // must not match, when set
	}{
		{"booster signature", parseBooster(booster(*gid, otherPriv), boostxPub, partnerPub), []error{ErrInvalidBooster, ErrInvalidSignature}, nil},
		{"booster alg", parseBooster(algNone(booster(*gid, boostxPriv)), boostxPub, partnerPub), []error{ErrInvalidBooster, ErrInvalidSignature}, nil},
		{"booster gid", parseBooster(booster(*foreignGID, boostxPriv), boostxPub, partnerPub), []error{ErrInvalidBooster, ErrInvalidGID, ErrInvalidSignature}, nil},
		{"booster gid.partner", parseBooster(booster(GID{}, boostxPriv), boostxPub, partnerPub), []error{ErrInvalidBooster, ErrMissingClaim}, nil},
		{"booster extract gid.partner", extract(ExtractBoosterPartner(booster(GID{}, boostxPriv))), []error{ErrInvalidBooster, ErrMissingClaim}, nil},
		{"booster nil boostx key", parseBooster(booster(*gid, boostxPriv), nil, partnerPub), []error{ErrInvalidPublicKey}, ErrInvalidBooster},
		{"booster nil partner key", parseBooster(booster(*gid, boostxPriv), boostxPub, nil), []error{ErrInvalidPublicKey}, ErrInvalidBooster},

		{"checkbet signature", parseCheckBet(checkBet(*gid, otherPriv), boostxPub, partnerPub), []error{ErrInvalidCheckBet, ErrInvalidSignature}, nil},
		{"checkbet alg", parseCheckBet(algNone(checkBet(*gid, boostxPriv)), boostxPub, partnerPub), []error{ErrInvalidCheckBet, ErrInvalidSignature}, nil},
		{"checkbet gid", parseCheckBet(checkBet(*foreignGID, boostxPriv), boostxPub, partnerPub), []error{ErrInvalidCheckBet, ErrInvalidGID, ErrInvalidSignature}, nil},
		{"checkbet gid.partner", parseCheckBet(checkBet(GID{}, boostxPriv), boostxPub, partnerPub), []error{ErrInvalidCheckBet, ErrMissingClaim}, nil},
		{"checkbet extract gid.partner", extract(ExtractCheckBetPartner(checkBet(GID{}, boostxPriv))), []error{ErrInvalidCheckBet, ErrMissingClaim}, nil},
		{"checkbet nil boostx key", parseCheckBet(checkBet(*gid, boostxPriv), nil, partnerPub), []error{ErrInvalidPublicKey}, ErrInvalidCheckBet},
		{"checkbet nil partner key", parseCheckBet(checkBet(*gid, boostxPriv), boostxPub, nil), []error{ErrInvalidPublicKey}, ErrInvalidCheckBet},

		{"gamepass signature", parseGamePass(gamePass(*gid, otherPriv), partnerPub), []error{ErrInvalidGamePass, ErrInvalidSignature}, nil},
		{"gamepass alg", parseGamePass(algNone(gamePass(*gid, partnerPriv)), partnerPub), []error{ErrInvalidGamePass, ErrInvalidSignature}, nil},
		{"gamepass gid", parseGamePass(gamePass(*foreignGID, partnerPriv), partnerPub), []error{ErrInvalidGamePass, ErrInvalidGID, ErrInvalidSignature}, nil},
		{"gamepass gid.partner", parseGamePass(gamePass(GID{}, partnerPriv), partnerPub), []error{ErrInvalidGamePass, ErrMissingClaim}, nil},
		{"gamepass extract gid.partner", extractGamePass(ExtractGamePassClaims(gamePass(GID{}, partnerPriv))), []error{ErrInvalidGamePass, ErrMissingClaim}, nil},
		{"gamepass nil key", parseGamePass(gamePass(*gid, partnerPriv), nil), []error{ErrInvalidPublicKey}, ErrInvalidGamePass},

		{"verifykeys signature", parseVerifyKeys(verifyKeys, partnerPub), []error{ErrInvalidVerifyKeys, ErrInvalidSignature}, nil},
		{"verifykeys alg", parseVerifyKeys(algNone(verifyKeys), boostxPub), []error{ErrInvalidVerifyKeys, ErrInvalidSignature}, nil},
		{"verifykeys nil key", parseVerifyKeys(verifyKeys, nil), []error{ErrInvalidPublicKey}, ErrInvalidVerifyKeys},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				if !errors.Is(tc.err, want) {
					t.Errorf("%v: does not match %v", tc.err, want)
				}
			}
			if tc.not != nil && errors.Is(tc.err, tc.not) {
				t.Errorf("%v: matches %v", tc.err, tc.not)
			}
		})
	}

	if reason := VerifyKeysReason(parseVerifyKeys(verifyKeys, partnerPub)); reason != VerifyKeysReasonSignature {
		t.Errorf("verifykeys signature: reason %q, want %q", reason, VerifyKeysReasonSignature)
	}
}
