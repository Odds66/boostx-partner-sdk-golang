package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const testPartnerID = "partner-abc"

func newVerifyKeysRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{"verifyKeysJWT": token})
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
	requestJWT, err := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, nonce)
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

	vk, err := tokens.ParseVerifyKeysResponseToken(resp.Result.ResponseJWT, &partnerPriv.PublicKey, testPartnerID, 0)
	if err != nil {
		t.Fatalf("parse response JWT: %v", err)
	}
	if vk.PartnerID != testPartnerID {
		t.Errorf("response partnerID: expected %q, got %q", testPartnerID, vk.PartnerID)
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
	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(wrongPriv, testPartnerID, 1)

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

	// iss is baked into the request creator, so the wrong-iss request is
	// hand-signed.
	requestJWT := signRaw(t, boostxPriv, map[string]any{
		"verifyKeys": map[string]any{"nonce": 1},
		"iss":        "not-boostx",
		"aud":        testPartnerID,
		"iat":        time.Now().Unix(),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonIssAud)
}

// TestVerifyKeysHandler_AudienceBoostxRejected asserts the handler rejects a
// request addressed to aud="boostx" — no real partner is the BoostX identity,
// so it is malformed and surfaces as "shape" before any key lookup.
func TestVerifyKeysHandler_AudienceBoostxRejected(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT := signRaw(t, boostxPriv, map[string]any{
		"verifyKeys": map[string]any{"nonce": 1},
		"iss":        tokens.BoostxIdentity,
		"aud":        tokens.BoostxIdentity,
		"iat":        time.Now().Unix(),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertReason(t, rec.Body.Bytes(), tokens.VerifyKeysReasonShape)
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
// "nonce-format" reason when ParseVerifyKeysRequestToken returns ErrVerifyKeysNonce.
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
// for a claim of the wrong JSON type.
func TestVerifyKeysHandler_Shape(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)

	claims := map[string]any{
		"verifyKeys": map[string]any{"nonce": 1},
		"iss":        tokens.BoostxIdentity,
		"aud":        testPartnerID,
		"iat":        strconv.FormatInt(time.Now().Unix(), 10), // a string, not a number
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

	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if msg := decodeErrorBody(t, rec.Body.Bytes()); msg != "failed to get partner private key" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

// TestVerifyKeysHandler_UnknownPartnerID asserts a key store reporting an
// unknown partner_id surfaces as the "iss-aud" reason: the aud names a partner
// this deployment does not serve, which is an id mismatch, not a key failure.
func TestVerifyKeysHandler_UnknownPartnerID(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	keyStore.pubErr = fmt.Errorf("%w %q", keys.ErrUnknownPartner, testPartnerID)
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	want := `invalid verifyKeysJWT: iss-aud (unknown partner "partner-abc")`
	if got := decodeErrorBody(t, rec.Body.Bytes()); got != want {
		t.Errorf("expected error=%q, got %q", want, got)
	}
}

// TestVerifyKeysHandler_UnknownPartnerPrivateKey asserts the iss-aud mapping
// covers the private-key lookup too: a store that serves the boostx key but
// reports ErrUnknownPartner for the signing key is still signalling an id
// this deployment does not serve, not a key failure.
func TestVerifyKeysHandler_UnknownPartnerPrivateKey(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	keyStore.privErr = fmt.Errorf("%w %q", keys.ErrUnknownPartner, testPartnerID)
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	want := `invalid verifyKeysJWT: iss-aud (unknown partner "partner-abc")`
	if got := decodeErrorBody(t, rec.Body.Bytes()); got != want {
		t.Errorf("expected error=%q, got %q", want, got)
	}
}

func TestVerifyKeysHandler_BoostxKeyLookupFailure(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	keyStore.pubErr = errors.New("kms timeout")
	handler := NewVerifyKeysHandler(keyStore)

	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)

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
	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, nonce)
	body, _ := json.Marshal(map[string]string{"verifyKeysJWT": requestJWT})

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
	vk, err := tokens.ParseVerifyKeysResponseToken(resp.Result.ResponseJWT, &partnerPriv.PublicKey, testPartnerID, 0)
	if err != nil {
		t.Fatalf("parse response JWT: %v", err)
	}
	if vk.Nonce != nonce {
		t.Errorf("expected echoed nonce=%d, got %d", nonce, vk.Nonce)
	}
}

// TestVerifyKeysHandler_IssIsAcceptedID pins that the store matches the
// partner id byte for byte, so the response iss is exactly the id accepted.
func TestVerifyKeysHandler_IssIsAcceptedID(t *testing.T) {
	boostxPriv, boostxPub := generateTestKeyPair(t)
	partnerPriv, partnerPub := generateTestKeyPair(t)
	ks := keys.NewMemoryKeyStore()
	if err := ks.Register("partner-a", partnerPub, partnerPriv, boostxPub); err != nil {
		t.Fatal(err)
	}
	handler := NewVerifyKeysHandler(ks)

	requestJWT, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, "Partner-A", 1)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))
	want := `invalid verifyKeysJWT: iss-aud (unknown partner "Partner-A")`
	if got := decodeErrorBody(t, rec.Body.Bytes()); rec.Code != http.StatusBadRequest || got != want {
		t.Errorf("Partner-A: got %d %q, want 400 %q", rec.Code, got, want)
	}

	requestJWT, _ = tokens.CreateVerifyKeysRequestToken(boostxPriv, "partner-a", 1)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, requestJWT))
	if rec.Code != http.StatusOK {
		t.Fatalf("partner-a: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result verifyKeysResult `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := tokens.ExtractJWTClaims(resp.Result.ResponseJWT, &claims); err != nil || claims.Iss != "partner-a" {
		t.Errorf("response iss: got %q, %v; want %q", claims.Iss, err, "partner-a")
	}
}

// TestVerifyKeysHandler_NoTrimming pins that the token is used exactly as
// received: whitespace in the header or payload segment is shape, in the
// signature segment signature.
func TestVerifyKeysHandler_NoTrimming(t *testing.T) {
	keyStore, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(keyStore)
	token, _ := tokens.CreateVerifyKeysRequestToken(boostxPriv, testPartnerID, 1)
	parts := strings.Split(token, ".")

	for name, tc := range map[string]struct{ token, reason string }{
		"leading space":    {" " + token, tokens.VerifyKeysReasonShape},
		"space in payload": {parts[0] + "." + parts[1][:4] + " " + parts[1][4:] + "." + parts[2], tokens.VerifyKeysReasonShape},
		"trailing newline": {token + "\n", tokens.VerifyKeysReasonSignature},
		"trailing CR LF":   {token + "\r\n", tokens.VerifyKeysReasonSignature},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newVerifyKeysRequest(t, tc.token))
		if got, want := decodeErrorBody(t, rec.Body.Bytes()), "invalid verifyKeysJWT: "+tc.reason; rec.Code != http.StatusBadRequest || got != want {
			t.Errorf("%s: got %d %q, want 400 %q", name, rec.Code, got, want)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newVerifyKeysRequest(t, token))
	if rec.Code != http.StatusOK {
		t.Errorf("the token as signed: got %d %s, want 200", rec.Code, rec.Body)
	}
}

// TestVerifyKeysHandler_ExtractionBeforeLookup pins what the handler refuses
// before any key lookup, all as shape: the payload format, the claim types and
// an aud that is empty or "boostx". The nonce, iss and the time window are
// judged after verification, so such a request reaches the key store.
func TestVerifyKeysHandler_ExtractionBeforeLookup(t *testing.T) {
	_, boostxPriv, _ := fullStore(t)
	handler := NewVerifyKeysHandler(&mockKeyStore{pubErr: errors.New("store down"), privErr: errors.New("store down")})
	now := time.Now().Unix()
	// claims is a valid request payload with key set to v, or without key when v is nil.
	claims := func(key string, v any) map[string]any {
		c := map[string]any{"verifyKeys": map[string]any{"nonce": 1}, "iss": tokens.BoostxIdentity, "aud": testPartnerID, "iat": now}
		c[key] = v
		if v == nil {
			delete(c, key)
		}
		return c
	}

	for name, payload := range map[string]any{
		"payload null":     nil,
		"exp null":         claims("exp", json.RawMessage("null")),
		"nbf string":       claims("nbf", "0"),
		"verifyKeys array": claims("verifyKeys", []int{1}),
		"iss number":       claims("iss", 1),
		"aud absent":       claims("aud", nil),
		"aud empty":        claims("aud", ""),
		"aud boostx":       claims("aud", tokens.BoostxIdentity),
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newVerifyKeysRequest(t, signRaw(t, boostxPriv, payload)))
		if got, want := decodeErrorBody(t, rec.Body.Bytes()), "invalid verifyKeysJWT: shape"; rec.Code != http.StatusBadRequest || got != want {
			t.Errorf("%s: got %d %q, want 400 %q", name, rec.Code, got, want)
		}
	}

	for name, payload := range map[string]map[string]any{
		"nonce 3.5":         claims("verifyKeys", map[string]any{"nonce": 3.5}),
		"nonce string":      claims("verifyKeys", map[string]any{"nonce": "1"}),
		"verifyKeys absent": claims("verifyKeys", nil),
		"iss other":         claims("iss", "other"),
		"iat 0":             claims("iat", 0),
		"exp passed":        claims("exp", 1),
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newVerifyKeysRequest(t, signRaw(t, boostxPriv, payload)))
		if got := decodeErrorBody(t, rec.Body.Bytes()); rec.Code != http.StatusInternalServerError || got != "failed to get boostx key" {
			t.Errorf("%s: got %d %q, want 500 from the store", name, rec.Code, got)
		}
	}
}
