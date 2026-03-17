package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

// mockKeyStore implements KeyStore for testing
type mockKeyStore struct {
	gamepassKey *ecdsa.PublicKey
	boostKey    *ecdsa.PublicKey
	err         error
}

func (m *mockKeyStore) GamePassPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return m.gamepassKey, m.err
}

func (m *mockKeyStore) BoostPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error) {
	return m.boostKey, m.err
}

// mockBetStore implements BetStoreUpdater (SetBoost only)
type mockBetStore struct {
	err error
}

func (m *mockBetStore) SetBoost(ctx context.Context, boost *tokens.Boost) error {
	return m.err
}

// mockFullBetStore implements both BetStoreUpdater and BetStoreChecker
type mockFullBetStore struct {
	active bool
	err    error
}

func (m *mockFullBetStore) SetBoost(ctx context.Context, boost *tokens.Boost) error {
	return m.err
}

func (m *mockFullBetStore) CheckBet(ctx context.Context, identity *tokens.Identity) (bool, error) {
	return m.active, m.err
}

func createTestIdentityToken(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()
	token, err := tokens.SignIdentityJWT("partner-123", "user-456", "bet-789", privateKey)
	if err != nil {
		t.Fatalf("failed to create identity token: %v", err)
	}
	return token
}

func TestCheckBetHandler_Success(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey}
	betStore := &mockFullBetStore{active: true}
	handler := NewCheckBetHandler(betStore, keyStore)

	token := createTestIdentityToken(t, partnerPrivKey)
	body, _ := json.Marshal(checkBetRequest{IdentityJWT: token})

	req := httptest.NewRequest(http.MethodPost, "/checkBet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp checkBetResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Active {
		t.Error("expected active=true")
	}
}

func TestCheckBetHandler_Inactive(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey}
	betStore := &mockFullBetStore{active: false}
	handler := NewCheckBetHandler(betStore, keyStore)

	token := createTestIdentityToken(t, partnerPrivKey)
	body, _ := json.Marshal(checkBetRequest{IdentityJWT: token})

	req := httptest.NewRequest(http.MethodPost, "/checkBet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp checkBetResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Active {
		t.Error("expected active=false")
	}
}

func TestCheckBetHandler_MethodNotAllowed(t *testing.T) {
	handler := NewCheckBetHandler(&mockFullBetStore{}, &mockKeyStore{})

	req := httptest.NewRequest(http.MethodGet, "/checkBet", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestCheckBetHandler_InvalidBody(t *testing.T) {
	handler := NewCheckBetHandler(&mockFullBetStore{}, &mockKeyStore{})

	req := httptest.NewRequest(http.MethodPost, "/checkBet", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestCheckBetHandler_InvalidToken(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey}
	betStore := &mockFullBetStore{active: true}
	handler := NewCheckBetHandler(betStore, keyStore)

	body, _ := json.Marshal(checkBetRequest{IdentityJWT: "invalid.token.here"})

	req := httptest.NewRequest(http.MethodPost, "/checkBet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	// Verify error message does not leak internal details
	var errResp errorResponse
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp.Error != "invalid identity token" {
		t.Errorf("expected generic error message, got %q", errResp.Error)
	}
}

func TestSetBoostHandler_Success(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)
	boostXPrivKey, boostXPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey, boostKey: boostXPubKey}
	betStore := &mockBetStore{}
	handler := NewSetBoostHandler(betStore, keyStore)

	// Create identity sub-token
	identityJWT, _ := tokens.SignIdentityJWT("partner-123", "user-456", "bet-789", partnerPrivKey)

	// Create a valid boost token with identity
	boostClaims := struct {
		Identity string  `json:"identity"`
		Round    int     `json:"round"`
		Boost    float64 `json:"boost"`
		Final    bool    `json:"final"`
		tokens.RegisteredClaims
	}{
		Identity: identityJWT,
		Round:    1,
		Boost:    1.5,
		Final:    false,
	}

	boostToken, _ := tokens.SignJWT(boostClaims, boostXPrivKey)
	body, _ := json.Marshal(setBoostRequest{BoostJWT: boostToken})

	req := httptest.NewRequest(http.MethodPost, "/setBoost", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify empty body (spec says just 200 OK)
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body, got %q", rec.Body.String())
	}
}

func TestMount_WithCheckBet(t *testing.T) {
	mux := http.NewServeMux()
	keyStore := &mockKeyStore{}
	betStore := &mockFullBetStore{} // implements BetStoreChecker

	Mount(mux, "/api/boostx", betStore, keyStore)

	// Both endpoints should be registered
	for _, endpoint := range []string{"/api/boostx/checkBet", "/api/boostx/setBoost"} {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
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

	// /setBoost should be registered
	req := httptest.NewRequest(http.MethodGet, "/api/boostx/setBoost", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("endpoint /api/boostx/setBoost not registered (got 404)")
	}

	// /checkBet should NOT be registered
	req = httptest.NewRequest(http.MethodGet, "/api/boostx/checkBet", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("endpoint /api/boostx/checkBet should not be registered, got %d", rec.Code)
	}
}
