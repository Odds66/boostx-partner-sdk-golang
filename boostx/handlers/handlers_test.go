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
	"time"

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

// mockBetStore implements BetStore for testing
type mockBetStore struct {
	active  bool
	betInfo *BetInfo
	err     error
}

func (m *mockBetStore) CheckBet(ctx context.Context, identity *tokens.Identity) (bool, error) {
	return m.active, m.err
}

func (m *mockBetStore) GetBet(ctx context.Context, identity *tokens.Identity) (*BetInfo, error) {
	return m.betInfo, m.err
}

func (m *mockBetStore) SetBoost(ctx context.Context, boost *tokens.Boost) error {
	return m.err
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
	betStore := &mockBetStore{active: true}
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
	betStore := &mockBetStore{active: false}
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
	handler := NewCheckBetHandler(&mockBetStore{}, &mockKeyStore{})

	req := httptest.NewRequest(http.MethodGet, "/checkBet", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestCheckBetHandler_InvalidBody(t *testing.T) {
	handler := NewCheckBetHandler(&mockBetStore{}, &mockKeyStore{})

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
	betStore := &mockBetStore{active: true}
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

func TestGetBetHandler_Success(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)

	betInfo := &BetInfo{
		BetTimestamp:   time.Now().Unix(),
		EventName:      "Test Event",
		EventMarket:    "Test Market",
		EventSelection: "Test Selection",
	}

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey}
	betStore := &mockBetStore{betInfo: betInfo}
	handler := NewGetBetHandler(betStore, keyStore)

	token := createTestIdentityToken(t, partnerPrivKey)
	body, _ := json.Marshal(getBetRequest{IdentityJWT: token})

	req := httptest.NewRequest(http.MethodPost, "/getBet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp BetInfo
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.EventName != "Test Event" {
		t.Errorf("expected event=%q, got %q", "Test Event", resp.EventName)
	}
}

func TestGetBetHandler_NotFound(t *testing.T) {
	partnerPrivKey, partnerPubKey := generateTestKeyPair(t)

	keyStore := &mockKeyStore{gamepassKey: partnerPubKey}
	betStore := &mockBetStore{betInfo: nil}
	handler := NewGetBetHandler(betStore, keyStore)

	token := createTestIdentityToken(t, partnerPrivKey)
	body, _ := json.Marshal(getBetRequest{IdentityJWT: token})

	req := httptest.NewRequest(http.MethodPost, "/getBet", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
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

	// Verify response is JSON (not empty)
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", rec.Header().Get("Content-Type"))
	}
}

func TestMount(t *testing.T) {
	mux := http.NewServeMux()
	keyStore := &mockKeyStore{}
	betStore := &mockBetStore{}

	Mount(mux, "/api/boostx", betStore, keyStore)

	// Verify all endpoints are registered by making requests
	endpoints := []string{"/api/boostx/checkBet", "/api/boostx/getBet", "/api/boostx/setBoost"}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// Should get 405 Method Not Allowed (not 404) since handlers exist
		if rec.Code == http.StatusNotFound {
			t.Errorf("endpoint %s not registered (got 404)", endpoint)
		}
	}
}
