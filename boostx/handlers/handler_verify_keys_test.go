package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const testPartnerID = "partner-abc"

func newVerifyKeysRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	body, err := json.Marshal(verifyKeysRequest{VerifyKeysJWT: token})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/verify-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// signRaw signs an arbitrary payload as the "boostx" caller would — used to
// hand-craft malformed requests that exercise the parse error paths.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, payload any) string {
	t.Helper()
	token, err := tokens.SignJWT(payload, priv)
	if err != nil {
		t.Fatalf("sign raw: %v", err)
	}
	return token
}

func fullStore(t *testing.T) (*mockKeyStore, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	boostxPriv, boostxPub := generateTestKeyPair(t)
	partnerPriv, _ := generateTestKeyPair(t)
	return &mockKeyStore{
		boostxPubKey:   boostxPub,
		partnerPrivKey: partnerPriv,
	}, boostxPriv, partnerPriv
}

func decodeErrorBody(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return resp.Error
}

func assertReason(t *testing.T, body []byte, want string) {
	t.Helper()
	got := decodeErrorBody(t, body)
	expected := "invalid verifyKeysJWT: " + want
	if got != expected {
		t.Errorf("expected error=%q, got %q", expected, got)
	}
}

func TestVerifyKeysHandler_Success(t *testing.T) {
	keyStore, boostxPriv, partnerPriv := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	const nonce = int32(42)
	requestJWT, err := tokens.CreateVerifyKeysToken(boostxPriv, tokens.BoostxIdentity, testPartnerID, nonce)
	if err != nil {
		t.Fatalf("create request JWT: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Result verifyKeysResult `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Result.ResponseJWT == "" {
		t.Fatal("expected responseJWT, got empty")
	}

	vk, err := tokens.ParseVerifyKeysToken(resp.Result.ResponseJWT, &partnerPriv.PublicKey, testPartnerID, tokens.BoostxIdentity, 0)
	if err != nil {
		t.Fatalf("parse response JWT: %v", err)
	}
	if vk.Issuer != testPartnerID {
		t.Errorf("response iss: expected %q, got %q", testPartnerID, vk.Issuer)
	}
	if vk.Audience != tokens.BoostxIdentity {
		t.Errorf("response aud: expected %q, got %q", tokens.BoostxIdentity, vk.Audience)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected echoed nonce=%d, got %d", nonce, vk.Nonce)
	}
}

func TestVerifyKeysHandler_InvalidBody(t *testing.T) {
	handler := NewVerifyKeysHandler(&mockKeyStore{})

	req := httptest.NewRequest(http.MethodPost, "/verify-keys", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestVerifyKeysHandler_InvalidSignature(t *testing.T) {
	keyStore, _, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	wrongPriv, _ := generateTestKeyPair(t)
	requestJWT, _ := tokens.CreateVerifyKeysToken(wrongPriv, tokens.BoostxIdentity, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonSignature)
}

func TestVerifyKeysHandler_IssAudMismatch(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysToken(boostxPriv, "not-boostx", testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonIssAud)
}

func TestVerifyKeysHandler_Stale(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	staleClaims := map[string]any{
		"verifyKeys": map[string]any{"nonce": 1},
		"iss":        tokens.BoostxIdentity,
		"aud":        testPartnerID,
		"iat":        time.Now().Add(-2 * time.Minute).Unix(),
	}
	requestJWT := signRaw(t, boostxPriv, staleClaims)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonStale)
}

// TestVerifyKeysHandler_NonceFormat asserts the handler surfaces the
// "nonce-format" reason when ParseVerifyKeysToken returns ErrVerifyKeysNonce.
// Exhaustive coverage of which inputs trigger that error lives in the token
// package; this test only validates the wire mapping.
func TestVerifyKeysHandler_NonceFormat(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	claims := map[string]any{
		"verifyKeys": map[string]any{"nonce": -5},
		"iss":        tokens.BoostxIdentity,
		"aud":        testPartnerID,
		"iat":        time.Now().Unix(),
	}
	requestJWT := signRaw(t, boostxPriv, claims)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonNonceFormat)
}

// TestVerifyKeysHandler_Shape asserts the handler surfaces the "shape" reason
// when a JSON-level decode failure propagates from ParseVerifyKeysToken.
func TestVerifyKeysHandler_Shape(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	claims := map[string]any{
		"verifyKeys": map[string]any{"nonce": 3.5}, // float fails int32 unmarshal
		"iss":        tokens.BoostxIdentity,
		"aud":        testPartnerID,
		"iat":        time.Now().Unix(),
	}
	requestJWT := signRaw(t, boostxPriv, claims)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonShape)
}

func TestVerifyKeysHandler_PrivateKeyLookupFailure(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	keyStore.privErr = errors.New("vault unavailable")
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysToken(boostxPriv, tokens.BoostxIdentity, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if msg := decodeErrorBody(t, rec.Body.Bytes()); msg != "failed to get partner private key" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestVerifyKeysHandler_BoostxKeyLookupFailure(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	keyStore.pubErr = errors.New("kms timeout")
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysToken(boostxPriv, tokens.BoostxIdentity, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestMount_VerifyKeysRoundTrip(t *testing.T) {
	keyStore, boostxPriv, partnerPriv := fullStore(t)
	keyStore.partnerPubKey = &partnerPriv.PublicKey
	betStore := &mockBetStore{}

	mux := http.NewServeMux()
	Mount(mux, "/api/boostx", betStore, keyStore)

	const nonce = int32(777)
	requestJWT, _ := tokens.CreateVerifyKeysToken(boostxPriv, tokens.BoostxIdentity, testPartnerID, nonce)
	body, _ := json.Marshal(verifyKeysRequest{VerifyKeysJWT: requestJWT})

	req := httptest.NewRequest(http.MethodPost, "/api/boostx/verify-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Result verifyKeysResult `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	vk, err := tokens.ParseVerifyKeysToken(resp.Result.ResponseJWT, &partnerPriv.PublicKey, testPartnerID, tokens.BoostxIdentity, 0)
	if err != nil {
		t.Fatalf("parse response JWT: %v", err)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected echoed nonce=%d, got %d", nonce, vk.Nonce)
	}
}

