package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// checkBetPayload and checkBetClaims build a CheckBet payload as BoostX signs it.
type checkBetPayload struct {
	GID GID `json:"gid"`
}

type checkBetClaims struct {
	CheckBet checkBetPayload `json:"checkbet"`
	IssuedAt int64           `json:"iat"`
}

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
		IssuedAt: time.Now().Unix(),
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
		IssuedAt: time.Now().Unix(),
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

	// Verify the claims are nested, not flat
	if _, ok := raw["gid"]; ok {
		t.Error("unexpected flat key 'gid' in JWT payload — should be nested under 'checkbet'")
	}
}

func TestExtractCheckBetPartner(t *testing.T) {
	partnerPrivKey, _ := generateTestKey(t)
	boostxPrivKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	claims := checkBetClaims{
		CheckBet: checkBetPayload{GID: *gid},
	}
	token, _ := SignJWT(claims, boostxPrivKey)

	partner, err := ExtractCheckBetPartner(token)
	if err != nil {
		t.Fatalf("ExtractCheckBetPartner failed: %v", err)
	}
	if partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", partner)
	}
}

// TestParseCheckBetTokenWithKeys pins that a CheckBet whose GID was signed with
// an earlier partner key passes when that key is in the list, and that a list
// with no usable key is refused before the token is read.
func TestParseCheckBetTokenWithKeys(t *testing.T) {
	oldPriv, oldPub := generateTestKey(t)
	_, newPub := generateTestKey(t)
	boostxPriv, boostxPub := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", oldPriv)
	token, _ := SignJWT(checkBetClaims{CheckBet: checkBetPayload{GID: *gid}}, boostxPriv)

	checkBet, err := ParseCheckBetTokenWithKeys(token, boostxPub, []*ecdsa.PublicKey{newPub, oldPub})
	if err != nil || checkBet.Bet != "bet" {
		t.Fatalf("new, old: got %+v, %v", checkBet, err)
	}

	_, err = ParseCheckBetTokenWithKeys(token, boostxPub, []*ecdsa.PublicKey{newPub})
	if !errors.Is(err, ErrInvalidCheckBet) || !errors.Is(err, ErrInvalidGID) || !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("new only: expected ErrInvalidCheckBet, ErrInvalidGID and ErrInvalidSignature, got %v", err)
	}

	p384 := &generateCurveKey(t, elliptic.P384()).PublicKey
	for name, keys := range map[string][]*ecdsa.PublicKey{
		"nil slice": nil, "empty": {}, "nil": {nil}, "zero value": {{}}, "P-384": {p384},
	} {
		if _, err := ParseCheckBetTokenWithKeys("garbage", boostxPub, keys); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("%s: expected ErrInvalidPublicKey, got %v", name, err)
		}
	}
}

// TestCheckBetClaims pins the claim step ExtractCheckBetPartner and
// ParseCheckBetToken share: exact member names, the last repeat winning, the
// gid shape, and iat required and exposed.
func TestCheckBetClaims(t *testing.T) {
	partnerPriv, partnerPub := generateTestKey(t)
	boostxPriv, boostxPub := generateTestKey(t)
	gid, _ := BuildGID("partner", "user", "bet", partnerPriv)
	token := func(payload string) string {
		return signRaw(t, boostxPriv, `{"alg":"ES256"}`, strings.ReplaceAll(payload, "@gid", gidJSON(gid)))
	}

	for payload, iat := range map[string]int64{
		`{"checkbet":{"gid":@gid},"iat":1700000000}`:                        1700000000,
		`{"checkbet":{"gid":@gid},"iat":1e3}`:                               1000,
		`{"checkbet":{"gid":null},"checkbet":{"gid":@gid},"iat":0,"iat":5}`: 5,
		`{"checkbet":{"gid":@gid,"GID":null},"CheckBet":null,"iat":0}`:      0,
	} {
		got, err := ParseCheckBetToken(token(payload), boostxPub, partnerPub)
		if err != nil || got.GID != *gid || got.IssuedAt != iat {
			t.Errorf("%s: expected iat %d, got %+v, %v", payload, iat, got, err)
		}
		if partner, err := ExtractCheckBetPartner(token(payload)); err != nil || partner != "partner" {
			t.Errorf("extract %s: expected partner, got %q, %v", payload, partner, err)
		}
	}

	// A gid member spelled in another case neither supplies nor overrides the named one.
	folded := token(`{"checkbet":{"gid":` + strings.Replace(gidJSON(gid), "{", `{"PARTNER":"other","Signature":"x",`, 1) + `},"iat":0}`)
	if got, err := ParseCheckBetToken(folded, boostxPub, partnerPub); err != nil || got.GID != *gid {
		t.Errorf("case-variant gid members: expected the GID, got %+v, %v", got, err)
	}
	if partner, err := ExtractCheckBetPartner(folded); err != nil || partner != "partner" {
		t.Errorf("extract, case-variant gid members: expected partner, got %q, %v", partner, err)
	}

	for payload, want := range map[string]error{
		`{"CheckBet":{"gid":@gid},"iat":0}`:                                 ErrMissingClaim,
		`{"checkbet":null,"iat":0}`:                                         ErrInvalidClaim,
		`{"checkbet":"x","iat":0}`:                                          ErrInvalidClaim,
		`{"checkbet":{},"iat":0}`:                                           ErrMissingClaim,
		`{"checkbet":{"gid":"x"},"iat":0}`:                                  ErrInvalidGID,
		`{"checkbet":{"gid":@gid},"checkbet":{"gid":null},"iat":0}`:         ErrInvalidGID,
		`{"checkbet":{"gid":{"partner":"p","user":"u","bet":"b"}},"iat":0}`: ErrInvalidGID,
		`{"checkbet":{"gid":@gid}}`:                                         ErrMissingClaim,
		`{"checkbet":{"gid":@gid},"Iat":0}`:                                 ErrMissingClaim,
		`{"checkbet":{"gid":@gid},"iat":true}`:                              ErrInvalidClaim,
		`{"checkbet":{"gid":@gid},"iat":0.5}`:                               ErrInvalidClaim,
		`{"checkbet":{"gid":@gid},"iat":0,"exp":0}`:                         ErrInvalidClaim,
	} {
		_, err := ParseCheckBetToken(token(payload), boostxPub, partnerPub)
		if !errors.Is(err, ErrInvalidCheckBet) || !errors.Is(err, want) || errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: expected ErrInvalidCheckBet and %v, got %v", payload, want, err)
		}
		if _, err := ExtractCheckBetPartner(token(payload)); !errors.Is(err, ErrInvalidCheckBet) || !errors.Is(err, want) {
			t.Errorf("extract %s: expected ErrInvalidCheckBet and %v, got %v", payload, want, err)
		}
	}

	// Unusable keys are reported before anything is read from the token.
	for name, err := range map[string]error{
		"BoostX key":  func() error { _, err := ParseCheckBetToken("garbage", nil, partnerPub); return err }(),
		"partner key": func() error { _, err := ParseCheckBetToken("garbage", boostxPub, nil); return err }(),
		"both":        func() error { _, err := ParseCheckBetToken("garbage", nil, nil); return err }(),
	} {
		if !errors.Is(err, ErrInvalidPublicKey) || errors.Is(err, ErrInvalidCheckBet) {
			t.Errorf("%s: expected ErrInvalidPublicKey alone, got %v", name, err)
		}
	}
}
