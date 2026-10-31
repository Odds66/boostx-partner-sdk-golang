package boostx_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// MemoryKeyStore must keep satisfying PartnerPublicKeysStore: a renamed method
// would silently leave the handlers on one partner public key.
var _ boostx.PartnerPublicKeysStore = (*boostx.MemoryKeyStore)(nil)

// unknownPartnerStore is a custom HandlersKeyStore that serves no partner at
// all, wrapping the facade's ErrUnknownPartner as the store contract requires.
type unknownPartnerStore struct{}

func (unknownPartnerStore) PartnerPublicKey(_ context.Context, partner string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("%w %q", boostx.ErrUnknownPartner, partner)
}

func (unknownPartnerStore) PartnerPrivateKey(_ context.Context, partner string) (*ecdsa.PrivateKey, error) {
	return nil, fmt.Errorf("%w %q", boostx.ErrUnknownPartner, partner)
}

func (unknownPartnerStore) BoostxPublicKey(_ context.Context, partner string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("%w %q", boostx.ErrUnknownPartner, partner)
}

// TestCustomKeyStore_ErrUnknownPartner pins the documented custom-store
// contract through the facade alone: wrapping boostx.ErrUnknownPartner for an
// unserved id yields the 400 mapping, reported on /verify-keys as iss-aud.
func TestCustomKeyStore_ErrUnknownPartner(t *testing.T) {
	boostxPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate boostx key: %v", err)
	}

	mux := http.NewServeMux()
	boostx.MountHandlers(mux, "/boostx", newExampleBetStore(), unknownPartnerStore{})

	token, err := boostx.CreateVerifyKeysRequestToken(boostxPriv, "partner-elsewhere", 9)
	if err != nil {
		t.Fatalf("create request token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"verifyKeysJWT": token})
	req := httptest.NewRequest(http.MethodPost, "/boostx/verify-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	want := `invalid verifyKeysJWT: iss-aud (unknown partner "partner-elsewhere")`
	if resp.Error != want {
		t.Errorf("expected error=%q, got %q", want, resp.Error)
	}
}

// rejectingBetStore refuses every round with the facade's ErrRoundRejected.
type rejectingBetStore struct{}

func (rejectingBetStore) SetBoost(context.Context, *boostx.Booster) error {
	return fmt.Errorf("bet settled: %w", boostx.ErrRoundRejected)
}

// TestErrRoundRejected pins the facade's ErrRoundRejected to the 400 answer.
func TestErrRoundRejected(t *testing.T) {
	partnerPriv, boostxPriv := newExampleKeyPair(), newExampleKeyPair()
	ks := boostx.NewMemoryKeyStore()
	if err := ks.Register("partner-1", &partnerPriv.PublicKey, partnerPriv, &boostxPriv.PublicKey); err != nil {
		t.Fatal(err)
	}
	gid, err := boostx.BuildGID("partner-1", "user-1", "bet-1", partnerPriv)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := tokens.SignJWT(map[string]any{"booster": map[string]any{"gid": gid, "round": 1, "boost": 1.5}}, boostxPriv)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	boostx.NewSetBoostHandler(rejectingBetStore{}, ks).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/set-boost", strings.NewReader(`{"boosterJWT":"`+jwt+`"}`)))
	if body := strings.TrimSpace(rec.Body.String()); rec.Code != http.StatusBadRequest || body != `{"error":"round rejected"}` {
		t.Errorf("expected 400 round rejected, got %d %s", rec.Code, body)
	}
}
