package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// TestMemoryBetStore_Replay drives /set-boost with round 2, then a late
// round 1, then round 2 again: every call answers 200 and the bet keeps
// round 2's boost.
func TestMemoryBetStore_Replay(t *testing.T) {
	partnerPriv := newKey(t)
	boostxPriv := newKey(t)
	keyStore := boostx.NewMemoryKeyStore()
	if err := keyStore.Register(partnerA, &partnerPriv.PublicKey, partnerPriv, &boostxPriv.PublicKey); err != nil {
		t.Fatal(err)
	}
	store := NewMemoryBetStore()
	store.AddBet(partnerA, userID, "bet-a")
	handler := boostx.NewSetBoostHandler(store, keyStore)

	gid, err := tokens.BuildGID(partnerA, userID, "bet-a", partnerPriv)
	if err != nil {
		t.Fatal(err)
	}
	setBoost := func(round int, boost float64) {
		t.Helper()
		type payload struct {
			GID   tokens.GID `json:"gid"`
			Round int        `json:"round"`
			Boost float64    `json:"boost"`
		}
		jwt, err := tokens.SignJWT(map[string]any{"booster": payload{*gid, round, boost}}, boostxPriv)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/set-boost",
			strings.NewReader(`{"boosterJWT":"`+jwt+`"}`)))
		if rec.Code != http.StatusOK {
			t.Fatalf("round %d: expected 200, got %d: %s", round, rec.Code, rec.Body)
		}
	}

	bet := store.bets[betKey{partnerA, userID, "bet-a"}]
	setBoost(2, 1.44)
	applied := bet.Booster
	if applied == nil || applied.Round != 2 {
		t.Fatalf("round 2 was not applied: got %+v", applied)
	}

	setBoost(1, 1.2) // late delivery of an older round
	if bet.Booster != applied {
		t.Errorf("late round 1 overwrote round 2: got %+v", bet.Booster)
	}

	setBoost(2, 1.44) // replay of the applied round
	if bet.Booster != applied {
		t.Errorf("replayed round 2 was applied again: got %+v", bet.Booster)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
