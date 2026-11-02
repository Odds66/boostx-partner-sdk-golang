package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// mockKeyStore implements KeyStore for testing. pubErr governs public-key
// lookups (PartnerPublicKey / BoostxPublicKey); privErr is independent so
// tests can simulate "private key lookup fails" in isolation.
type mockKeyStore struct {
	partnerPubKey  *ecdsa.PublicKey
	partnerPrivKey *ecdsa.PrivateKey
	boostxPubKey   *ecdsa.PublicKey
	pubErr         error
	privErr        error
}

func (m *mockKeyStore) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	return m.partnerPubKey, m.pubErr
}

func (m *mockKeyStore) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	return m.partnerPrivKey, m.privErr
}

func (m *mockKeyStore) BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	return m.boostxPubKey, m.pubErr
}

// mockBetStore implements BetStoreUpdater (SetBoost only)
type mockBetStore struct {
	err error
}

func (m *mockBetStore) SetBoost(ctx context.Context, booster *tokens.Booster) error {
	return m.err
}

// mockFullBetStore implements both BetStoreUpdater and BetStoreChecker
type mockFullBetStore struct {
	active bool
	err    error
}

func (m *mockFullBetStore) SetBoost(ctx context.Context, booster *tokens.Booster) error {
	return m.err
}

func (m *mockFullBetStore) CheckBet(ctx context.Context, gid *tokens.GID) (bool, error) {
	return m.active, m.err
}

func createTestCheckBetToken(t *testing.T, partnerPrivKey *ecdsa.PrivateKey, boostxPrivKey *ecdsa.PrivateKey) string {
	t.Helper()
	gid, err := tokens.BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	if err != nil {
		t.Fatalf("failed to build GID: %v", err)
	}

	claims := map[string]any{"checkbet": map[string]any{"gid": gid}, "iat": time.Now().Unix()}

	token, err := tokens.SignJWT(claims, boostxPrivKey)
	if err != nil {
		t.Fatalf("failed to create checkbet token: %v", err)
	}
	return token
}

func TestCheckBetHandler_Success(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)
	boostxPrivKey, boostxPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{partnerPubKey: partnerPubKey, boostxPubKey: boostxPubKey}
	betStore := &mockFullBetStore{active: true}
	handler := NewCheckBetHandler(betStore, keyStore)

	token := createTestCheckBetToken(t, partnerPrivKey, boostxPrivKey)
	body, _ := json.Marshal(map[string]string{"checkbetJWT": token})

	req := httptest.NewRequest(http.MethodPost, "/check-bet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp struct {
		Result checkBetResponse `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Result.Active {
		t.Error("expected result.active=true")
	}
}

func TestCheckBetHandler_Inactive(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)
	boostxPrivKey, boostxPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{partnerPubKey: partnerPubKey, boostxPubKey: boostxPubKey}
	betStore := &mockFullBetStore{active: false}
	handler := NewCheckBetHandler(betStore, keyStore)

	token := createTestCheckBetToken(t, partnerPrivKey, boostxPrivKey)
	body, _ := json.Marshal(map[string]string{"checkbetJWT": token})

	req := httptest.NewRequest(http.MethodPost, "/check-bet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp struct {
		Result checkBetResponse `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Result.Active {
		t.Error("expected result.active=false")
	}
}

func TestCheckBetHandler_InvalidBody(t *testing.T) {
	handler := NewCheckBetHandler(&mockFullBetStore{}, &mockKeyStore{})

	req := httptest.NewRequest(http.MethodPost, "/check-bet", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestCheckBetHandler_InvalidToken(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{partnerPubKey: partnerPubKey, boostxPubKey: boostxPubKey}
	betStore := &mockFullBetStore{active: true}
	handler := NewCheckBetHandler(betStore, keyStore)

	body, _ := json.Marshal(map[string]string{"checkbetJWT": "invalid.token.here"})

	req := httptest.NewRequest(http.MethodPost, "/check-bet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestSetBoostHandler_Success(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)
	boostxPrivKey, boostxPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{partnerPubKey: partnerPubKey, boostxPubKey: boostxPubKey}
	betStore := &mockBetStore{}
	handler := NewSetBoostHandler(betStore, keyStore)

	// Build GID
	gid, _ := tokens.BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)

	// Create a valid booster token with nested structure
	boosterClaims := struct {
		Booster struct {
			GID     tokens.GID `json:"gid"`
			Round   int        `json:"round"`
			Boost   float64    `json:"boost"`
			Final   bool       `json:"final"`
			Jackpot bool       `json:"jackpot"`
		} `json:"booster"`
		tokens.RegisteredClaims
	}{}
	boosterClaims.Booster.GID = *gid
	boosterClaims.Booster.Round = 1
	boosterClaims.Booster.Boost = 1.5
	boosterClaims.Booster.Final = false
	boosterClaims.IssuedAt = time.Now().Unix()

	boosterToken, _ := tokens.SignJWT(boosterClaims, boostxPrivKey)
	body, _ := json.Marshal(map[string]string{"boosterJWT": boosterToken})

	req := httptest.NewRequest(http.MethodPost, "/set-boost", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify {"result":{"ok":true}} response envelope
	var resp struct {
		Result struct {
			OK bool `json:"ok"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Result.OK {
		t.Error("expected result.ok=true")
	}
}

func TestMount_WithCheckBet(t *testing.T) {
	mux := http.NewServeMux()
	keyStore := &mockKeyStore{}
	betStore := &mockFullBetStore{} // implements BetStoreChecker

	Mount(mux, "/api/boostx", betStore, keyStore)

	// Both endpoints should be registered
	for _, endpoint := range []string{"/api/boostx/check-bet", "/api/boostx/set-boost"} {
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code == http.StatusNotFound {
			t.Errorf("endpoint %s not registered (got 404)", endpoint)
		}
	}
}

func TestMount_WithoutCheckBet(t *testing.T) {
	mux := http.NewServeMux()
	keyStore := &mockKeyStore{}
	betStore := &mockBetStore{} // does NOT implement BetStoreChecker

	Mount(mux, "/api/boostx", betStore, keyStore)

	// /set-boost should be registered
	req := httptest.NewRequest(http.MethodPost, "/api/boostx/set-boost", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("endpoint /api/boostx/set-boost not registered (got 404)")
	}

	// /check-bet should NOT be registered
	req = httptest.NewRequest(http.MethodGet, "/api/boostx/check-bet", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("endpoint /api/boostx/check-bet should not be registered, got %d", rec.Code)
	}
}

// TestSetBoostHandler_UnknownPartner verifies a key store reporting an unknown
// partner_id yields 400 (a request problem), not 500 (a backend failure).
func TestSetBoostHandler_UnknownPartner(t *testing.T) {
	partnerPrivKey, _ := generateTestKeyPair(t)
	boostxPrivKey, _ := generateTestKeyPair(t)

	keyStore := &mockKeyStore{pubErr: fmt.Errorf("%w %q", keys.ErrUnknownPartner, "partner-123")}
	handler := NewSetBoostHandler(&mockBetStore{}, keyStore)

	boosterToken := createTestBoosterToken(t, partnerPrivKey, boostxPrivKey)
	body, _ := json.Marshal(map[string]string{"boosterJWT": boosterToken})

	req := httptest.NewRequest(http.MethodPost, "/set-boost", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp errorResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	want := `unknown partner "partner-123"`
	if rec.Code != http.StatusBadRequest || resp.Error != want {
		t.Errorf("unknown partner: expected 400 %q, got %d %q", want, rec.Code, resp.Error)
	}
}

func createTestBoosterToken(t *testing.T, partnerPrivKey *ecdsa.PrivateKey, boostxPrivKey *ecdsa.PrivateKey) string {
	t.Helper()
	gid, err := tokens.BuildGID("partner-123", "user-456", "bet-789", partnerPrivKey)
	if err != nil {
		t.Fatalf("failed to build GID: %v", err)
	}
	claims := map[string]any{
		"booster": map[string]any{"gid": gid, "round": 1, "boost": 1.5, "final": false, "jackpot": false},
		"iat":     time.Now().Unix(),
	}
	token, err := tokens.SignJWT(claims, boostxPrivKey)
	if err != nil {
		t.Fatalf("failed to create booster token: %v", err)
	}
	return token
}

// post sends {field: token} to h and returns the status and the trimmed body.
func post(h http.Handler, field, token string) (int, string) {
	body, _ := json.Marshal(map[string]string{field: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// multiKeyStore implements PartnerPublicKeysStore; its PartnerPublicKey fails
// the test, so a pass shows the handlers prefer the list.
type multiKeyStore struct {
	*mockKeyStore
	t    *testing.T
	pubs []*ecdsa.PublicKey
	err  error
}

func (m multiKeyStore) PartnerPublicKey(context.Context, string) (*ecdsa.PublicKey, error) {
	m.t.Fatal("PartnerPublicKey called on a PartnerPublicKeysStore")
	return nil, nil
}

func (m multiKeyStore) PartnerPublicKeys(context.Context, string) ([]*ecdsa.PublicKey, error) {
	return m.pubs, m.err
}

// TestHandlers_EarlierPartnerKey pins that /set-boost and /check-bet accept a
// GID signed with an earlier partner key the store still lists.
func TestHandlers_EarlierPartnerKey(t *testing.T) {
	oldPriv, oldPub := generateTestKeyPair(t)
	_, newPub := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	booster := createTestBoosterToken(t, oldPriv, boostxPriv)
	checkBet := createTestCheckBetToken(t, oldPriv, boostxPriv)

	both := keys.NewMemoryKeyStore()
	_ = both.RegisterWithPartnerPublicKeys("partner-123", []*ecdsa.PublicKey{newPub, oldPub}, nil, boostxPub)
	newOnly := keys.NewMemoryKeyStore()
	_ = newOnly.Register("partner-123", newPub, nil, boostxPub)
	listed := multiKeyStore{&mockKeyStore{boostxPubKey: boostxPub}, t, []*ecdsa.PublicKey{newPub, oldPub}, nil}

	tests := []struct {
		name     string
		ks       KeyStore
		wantCode int
		wantBody [2]string // set-boost, check-bet
	}{
		{"memory store, new and old", both, 200, [2]string{`{"result":{"ok":true}}`, `{"result":{"active":true}}`}},
		{"custom store, new and old", listed, 200, [2]string{`{"result":{"ok":true}}`, `{"result":{"active":true}}`}},
		{"memory store, new only", newOnly, 400, [2]string{`{"error":"invalid booster token"}`, `{"error":"invalid checkbet token"}`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := post(NewSetBoostHandler(&mockBetStore{}, tc.ks), "boosterJWT", booster); code != tc.wantCode || body != tc.wantBody[0] {
				t.Errorf("set-boost: got %d %s", code, body)
			}
			if code, body := post(NewCheckBetHandler(&mockFullBetStore{active: true}, tc.ks), "checkbetJWT", checkBet); code != tc.wantCode || body != tc.wantBody[1] {
				t.Errorf("check-bet: got %d %s", code, body)
			}
		})
	}
}

// TestHandlers_PartnerPublicKeysErrors pins how a PartnerPublicKeys failure is
// answered: an unknown partner 400, any other error 500, and an empty list,
// like a nil key, 500 "failed to verify token".
func TestHandlers_PartnerPublicKeysErrors(t *testing.T) {
	partnerPriv, _ := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	booster := createTestBoosterToken(t, partnerPriv, boostxPriv)
	checkBet := createTestCheckBetToken(t, partnerPriv, boostxPriv)

	tests := []struct {
		name     string
		pubs     []*ecdsa.PublicKey
		err      error
		wantCode int
		wantBody string
	}{
		{"unknown partner", nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, "partner-123"), 400, `{"error":"unknown partner \"partner-123\""}`},
		{"store failure", nil, errors.New("db down"), 500, `{"error":"failed to get partner key"}`},
		{"empty list", []*ecdsa.PublicKey{}, nil, 500, `{"error":"failed to verify token"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks := multiKeyStore{&mockKeyStore{boostxPubKey: boostxPub}, t, tc.pubs, tc.err}
			if code, body := post(NewSetBoostHandler(&mockBetStore{}, ks), "boosterJWT", booster); code != tc.wantCode || body != tc.wantBody {
				t.Errorf("set-boost: got %d %s", code, body)
			}
			if code, body := post(NewCheckBetHandler(&mockFullBetStore{}, ks), "checkbetJWT", checkBet); code != tc.wantCode || body != tc.wantBody {
				t.Errorf("check-bet: got %d %s", code, body)
			}
		})
	}
}

// TestHandlers_NilKeysFromStore pins that a store answering (nil, nil) is
// answered 500 "failed to verify token" on every endpoint, not as a bad token,
// and a nil partner private key on /verify-keys 500 "failed to sign response".
func TestHandlers_NilKeysFromStore(t *testing.T) {
	partnerPriv, partnerPub := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	verifyKeys, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)

	ks := &mockKeyStore{}
	for _, tc := range []struct {
		name         string
		handler      http.Handler
		field, token string
	}{
		{"set-boost", NewSetBoostHandler(&mockBetStore{}, ks), "boosterJWT", createTestBoosterToken(t, partnerPriv, boostxPriv)},
		{"check-bet", NewCheckBetHandler(&mockFullBetStore{}, ks), "checkbetJWT", createTestCheckBetToken(t, partnerPriv, boostxPriv)},
		{"verify-keys", NewVerifyKeysHandler(ks), "verifyKeysJWT", verifyKeys},
	} {
		if code, body := post(tc.handler, tc.field, tc.token); code != 500 || body != `{"error":"failed to verify token"}` {
			t.Errorf("%s: got %d %s", tc.name, code, body)
		}
	}

	ks = &mockKeyStore{partnerPubKey: partnerPub, boostxPubKey: boostxPub}
	if code, body := post(NewVerifyKeysHandler(ks), "verifyKeysJWT", verifyKeys); code != 500 || body != `{"error":"failed to sign response"}` {
		t.Errorf("verify-keys, nil private key: got %d %s", code, body)
	}
}

// TestSetBoostHandler_StoreErrors pins the status of a SetBoost error:
// ErrRoundRejected, wrapped or joined, is 400; anything else is 500.
func TestSetBoostHandler_StoreErrors(t *testing.T) {
	partnerPriv, partnerPub := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	booster := createTestBoosterToken(t, partnerPriv, boostxPriv)
	ks := &mockKeyStore{partnerPubKey: partnerPub, boostxPubKey: boostxPub}

	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"rejected", ErrRoundRejected, 400, `{"error":"round rejected"}`},
		{"wrapped", fmt.Errorf("bet settled: %w", ErrRoundRejected), 400, `{"error":"round rejected"}`},
		{"joined", errors.Join(errors.New("x"), ErrRoundRejected), 400, `{"error":"round rejected"}`},
		{"failure", errors.New("db down"), 500, `{"error":"failed to set boost"}`},
	}
	for _, tc := range tests {
		if code, body := post(NewSetBoostHandler(&mockBetStore{err: tc.err}, ks), "boosterJWT", booster); code != tc.wantCode || body != tc.wantBody {
			t.Errorf("%s: got %d %s, want %d %s", tc.name, code, body, tc.wantCode, tc.wantBody)
		}
	}
}

// TestCheckBetHandler_StoreError pins that a CheckBet error is answered 500.
func TestCheckBetHandler_StoreError(t *testing.T) {
	partnerPriv, partnerPub := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	ks := &mockKeyStore{partnerPubKey: partnerPub, boostxPubKey: boostxPub}

	code, body := post(NewCheckBetHandler(&mockFullBetStore{err: errors.New("db down")}, ks), "checkbetJWT", createTestCheckBetToken(t, partnerPriv, boostxPriv))
	if code != 500 || body != `{"error":"failed to check bet"}` {
		t.Errorf("got %d %s", code, body)
	}
}

// TestConstructors_NilArguments pins the panic message for an untyped nil
// store or key store, raised when the handler is built.
func TestConstructors_NilArguments(t *testing.T) {
	ks, bs := &mockKeyStore{}, &mockFullBetStore{}
	tests := []struct {
		name string
		call func()
		want string
	}{
		{"NewSetBoostHandler store", func() { NewSetBoostHandler(nil, ks) }, "boostx: nil bet store"},
		{"NewSetBoostHandler keys", func() { NewSetBoostHandler(bs, nil) }, "boostx: nil key store"},
		{"NewCheckBetHandler store", func() { NewCheckBetHandler(nil, ks) }, "boostx: nil bet store"},
		{"NewCheckBetHandler keys", func() { NewCheckBetHandler(bs, nil) }, "boostx: nil key store"},
		{"NewVerifyKeysHandler keys", func() { NewVerifyKeysHandler(nil) }, "boostx: nil key store"},
		{"Mount store", func() { Mount(http.NewServeMux(), "", nil, ks) }, "boostx: nil bet store"},
		{"Mount keys", func() { Mount(http.NewServeMux(), "", bs, nil) }, "boostx: nil key store"},
		{"Mount keys, no checker", func() { Mount(http.NewServeMux(), "", &mockBetStore{}, nil) }, "boostx: nil key store"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != tc.want {
					t.Errorf("panic %v, want %q", got, tc.want)
				}
			}()
			tc.call()
		})
	}
}

// TestHandlers_ClaimFaultsBeforeKeyLookup pins that a token whose claims fail
// is answered 400 before any key-store lookup: this store answers every lookup
// with an error that would give 500.
func TestHandlers_ClaimFaultsBeforeKeyLookup(t *testing.T) {
	partnerPriv, _ := generateTestKeyPair(t)
	boostxPriv, _ := generateTestKeyPair(t)
	store := &mockKeyStore{pubErr: errors.New("store down"), privErr: errors.New("store down")}
	gid, _ := tokens.BuildGID("partner-123", "user-456", "bet-789", partnerPriv)
	noSig := map[string]any{"partner": gid.Partner, "user": gid.User, "bet": gid.Bet}
	now := time.Now().Unix()
	sign := func(claims map[string]any) string {
		token, err := tokens.SignJWT(claims, boostxPriv)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	booster := func(gid any, round int, claims map[string]any) string {
		claims["booster"] = map[string]any{"gid": gid, "round": round, "boost": 1.5, "final": false, "jackpot": false}
		return sign(claims)
	}
	setBoost := NewSetBoostHandler(&mockBetStore{}, store)
	checkBet := NewCheckBetHandler(&mockFullBetStore{}, store)
	// Extraction reads neither the header nor the signature segment.
	b64 := base64.RawURLEncoding.EncodeToString
	loneSurrogate := b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte(`{"booster":{"gid":{"partner":"partner-123","user":"`+
		string(rune(92))+`ud800","bet":"bet-789","signature":"`+gid.Signature+`"},"round":1,"boost":1.5,"final":false,"jackpot":false},"iat":0}`)) +
		"." + gid.Signature

	for name, tc := range map[string]struct {
		h            http.Handler
		field, token string
		want         string
	}{
		"booster round 0":                {setBoost, "boosterJWT", booster(gid, 0, map[string]any{"iat": now}), `{"error":"invalid booster token"}`},
		"booster gid without signature":  {setBoost, "boosterJWT", booster(noSig, 1, map[string]any{"iat": now}), `{"error":"invalid booster token"}`},
		"booster without iat":            {setBoost, "boosterJWT", booster(gid, 1, map[string]any{}), `{"error":"invalid booster token"}`},
		"booster lone surrogate escape":  {setBoost, "boosterJWT", loneSurrogate, `{"error":"invalid booster token"}`},
		"checkbet gid without signature": {checkBet, "checkbetJWT", sign(map[string]any{"checkbet": map[string]any{"gid": noSig}, "iat": now}), `{"error":"invalid checkbet token"}`},
		"verify-keys iat string": {NewVerifyKeysHandler(store), "verifyKeysJWT",
			sign(map[string]any{"verifyKeys": map[string]any{"nonce": 1}, "iss": "boostx", "aud": "partner-123", "iat": "1"}),
			`{"error":"invalid verifyKeysJWT: shape"}`},
	} {
		if code, body := post(tc.h, tc.field, tc.token); code != http.StatusBadRequest || body != tc.want {
			t.Errorf("%s: got %d %s, want 400 %s", name, code, body, tc.want)
		}
	}

	// With every claim valid the same request reaches the store.
	code, body := post(setBoost, "boosterJWT", booster(gid, 1, map[string]any{"iat": now}))
	if code != http.StatusInternalServerError || body != `{"error":"failed to get boostx key"}` {
		t.Errorf("valid claims: got %d %s, want 500 from the store", code, body)
	}
}

// TestHandlers_RequestBody pins the body rule the three handlers share: at
// most 64 KiB counted over every byte, valid UTF-8 holding one JSON value that
// is an object or null, and the token read under its exact name as a string;
// an absent or null token is the empty token, which the token rules refuse.
func TestHandlers_RequestBody(t *testing.T) {
	partnerPriv, partnerPub := generateTestKeyPair(t)
	boostxPriv, boostxPub := generateTestKeyPair(t)
	store := &mockKeyStore{partnerPubKey: partnerPub, partnerPrivKey: partnerPriv, boostxPubKey: boostxPub}
	verifyKeysToken, err := tokens.CreateVerifyKeysRequestToken(boostxPriv, "partner-123", 1)
	if err != nil {
		t.Fatal(err)
	}
	const badBody = `{"error":"invalid request body"}`

	for _, h := range []struct {
		name, field, token, emptyToken string
		handler                        http.Handler
	}{
		{"set-boost", "boosterJWT", createTestBoosterToken(t, partnerPriv, boostxPriv),
			`{"error":"invalid booster token"}`, NewSetBoostHandler(&mockBetStore{}, store)},
		{"check-bet", "checkbetJWT", createTestCheckBetToken(t, partnerPriv, boostxPriv),
			`{"error":"invalid checkbet token"}`, NewCheckBetHandler(&mockFullBetStore{}, store)},
		{"verify-keys", "verifyKeysJWT", verifyKeysToken,
			`{"error":"invalid verifyKeysJWT: shape"}`, NewVerifyKeysHandler(store)},
	} {
		member := `"` + h.field + `":"` + h.token + `"`
		padded := func(n int) string { // {member} followed by spaces up to n bytes
			body := "{" + member + "}"
			return body + strings.Repeat(" ", n-len(body))
		}
		for _, tc := range []struct {
			name, body string
			code       int
			want       string // checked when not empty
		}{
			{"exactly 64 KiB", padded(maxRequestBodySize), http.StatusOK, ""},
			{"one byte more", padded(maxRequestBodySize + 1), http.StatusBadRequest, badBody},
			{"whitespace around", " \r\n{" + member + "}\t ", http.StatusOK, ""},
			{"other members", `{"x":[1,{}],` + member + `,"y":null}`, http.StatusOK, ""},
			{"repeated name, last wins", `{"` + h.field + `":"junk",` + member + `}`, http.StatusOK, ""},
			{"trailing data", "{" + member + "} {}", http.StatusBadRequest, badBody},
			{"byte order mark", "\xef\xbb\xbf{" + member + "}", http.StatusBadRequest, badBody},
			{"invalid UTF-8 in another member", "{\"x\":\"\xff\"," + member + "}", http.StatusBadRequest, badBody},
			{"empty", "", http.StatusBadRequest, badBody},
			{"array", "[" + member[len(h.field)+3:] + "]", http.StatusBadRequest, badBody},
			{"string", `"x"`, http.StatusBadRequest, badBody},
			{"number token", `{"` + h.field + `":1}`, http.StatusBadRequest, badBody},
			{"object token", `{"` + h.field + `":{}}`, http.StatusBadRequest, badBody},
			{"null body", "null", http.StatusBadRequest, h.emptyToken},
			{"null token", `{"` + h.field + `":null}`, http.StatusBadRequest, h.emptyToken},
			{"absent token", "{}", http.StatusBadRequest, h.emptyToken},
			{"name in another case", `{"` + strings.ToUpper(h.field) + `":"` + h.token + `"}`, http.StatusBadRequest, h.emptyToken},
		} {
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)))
			body := strings.TrimSpace(rec.Body.String())
			if rec.Code != tc.code || tc.want != "" && body != tc.want {
				t.Errorf("%s, %s: got %d %s, want %d %s", h.name, tc.name, rec.Code, body, tc.code, tc.want)
			}
		}
	}
}

// TestHandlers_MethodNotAllowed pins that each standalone handler answers a
// method other than POST 405 with Allow: POST before reading the body or
// calling a store, while a POST passes the gate.
func TestHandlers_MethodNotAllowed(t *testing.T) {
	store := &mockKeyStore{pubErr: errors.New("store down"), privErr: errors.New("store down")}
	for name, h := range map[string]http.Handler{
		"set-boost":   NewSetBoostHandler(&mockBetStore{}, store),
		"check-bet":   NewCheckBetHandler(&mockFullBetStore{}, store),
		"verify-keys": NewVerifyKeysHandler(store),
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, "post"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "/", strings.NewReader("{}")))
			body := strings.TrimSpace(rec.Body.String())
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" || body != `{"error":"method not allowed"}` {
				t.Errorf("%s %s: got %d Allow %q %s", name, method, rec.Code, rec.Header().Get("Allow"), body)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("")))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Allow") != "" {
			t.Errorf("%s POST: got %d Allow %q, want 400 from the body check", name, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

// TestMount_Routing pins the paths Mount serves: exactly <prefix>/<name>, case
// included, with the query ignored, a trailing slash not served, and another
// method answered 405.
func TestMount_Routing(t *testing.T) {
	for _, prefix := range []string{"/api/boostx", "/api/boostx/"} {
		mux := http.NewServeMux()
		Mount(mux, prefix, &mockFullBetStore{}, &mockKeyStore{})
		for _, tc := range []struct {
			method, target string
			want           int
		}{
			{http.MethodPost, "/api/boostx/set-boost", http.StatusBadRequest},
			{http.MethodPost, "/api/boostx/check-bet", http.StatusBadRequest},
			{http.MethodPost, "/api/boostx/verify-keys", http.StatusBadRequest},
			{http.MethodPost, "/api/boostx/set-boost?x=1", http.StatusBadRequest},
			{http.MethodPost, "/api/boostx/Set-Boost", http.StatusNotFound},
			{http.MethodPost, "/api/boostx/set-boost/", http.StatusNotFound},
			{http.MethodPost, "/api/boostx/x/set-boost", http.StatusNotFound},
			{http.MethodGet, "/api/boostx/set-boost", http.StatusMethodNotAllowed},
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, strings.NewReader("")))
			if rec.Code != tc.want {
				t.Errorf("prefix %q, %s %s: got %d, want %d", prefix, tc.method, tc.target, rec.Code, tc.want)
			}
			if tc.want == http.StatusMethodNotAllowed && !strings.Contains(rec.Header().Get("Allow"), "POST") {
				t.Errorf("prefix %q, %s %s: Allow %q", prefix, tc.method, tc.target, rec.Header().Get("Allow"))
			}
		}
	}
}

// TestMount_Prefix pins that Mount takes an empty prefix or a clean path
// starting with "/", one trailing slash trimmed, and panics on any other.
func TestMount_Prefix(t *testing.T) {
	mount := func(prefix string) (msg any) {
		defer func() { msg = recover() }()
		Mount(http.NewServeMux(), prefix, &mockBetStore{}, &mockKeyStore{})
		return nil
	}
	for _, prefix := range []string{"", "/", "/api", "/api/boostx", "/api/boostx/", "/v1.2/boost-x_api"} {
		if msg := mount(prefix); msg != nil {
			t.Errorf("prefix %q: panic %v", prefix, msg)
		}
	}
	for _, prefix := range []string{"api/boostx", "example.com/api", "//", "/api//boostx", "/api/boostx//",
		"/api/./boostx", "/api/../boostx", "/api/.", "/api/{id}", "/api/boostx}", "/api boostx", "/api\tboostx"} {
		want := fmt.Sprintf(`boostx: mount prefix %q must be empty or a clean path starting with "/"`, strings.TrimSuffix(prefix, "/"))
		if msg := mount(prefix); msg != want {
			t.Errorf("prefix %q: panic %v, want %q", prefix, msg, want)
		}
	}
}
