package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func testKeyStore(t *testing.T) *keys.MemoryKeyStore {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks := keys.NewMemoryKeyStore()
	if err := ks.Register("partner-1", nil, key, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	return ks
}

// testSettlementParams returns a settlement the token layer accepts, so these
// tests exercise the HTTP call rather than parameter validation.
func testSettlementParams() tokens.SettlementParams {
	return tokens.SettlementParams{
		Partner:   "partner-1",
		User:      "user-1",
		Bet:       "bet-1",
		Status:    "win",
		Amount:    42.50,
		Currency:  "USD",
		Version:   time.Now().UnixMilli(),
		XSettle:   new(2.5),
		SettledAt: time.Now().UnixMilli(),
	}
}

func TestSubmitSettlement_Success(t *testing.T) {
	var got settlementRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/integration/settlement" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]bool{"ok": true}})
	}))
	defer srv.Close()

	ks := testKeyStore(t)
	c := New(ks, WithBaseURL(srv.URL))
	err := c.SubmitSettlement(t.Context(), testSettlementParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SettlementJWT == "" {
		t.Error("settlementJWT is empty, expected a signed JWT")
	}
}

func TestSubmitSettlement_ErrorResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       any
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "400 with error envelope",
			status:     http.StatusBadRequest,
			body:       map[string]string{"error": "invalid settlementJWT"},
			wantStatus: 400,
			wantMsg:    "invalid settlementJWT",
		},
		{
			name:       "400 rejected field, status echoed in the body",
			status:     http.StatusBadRequest,
			body:       map[string]any{"status": 400, "error": "invalid-xsettle"},
			wantStatus: 400,
			wantMsg:    "invalid-xsettle",
		},
		{
			name:       "401 unauthorized",
			status:     http.StatusUnauthorized,
			body:       map[string]any{"status": 401, "error": "unauthorized"},
			wantStatus: 401,
			wantMsg:    "unauthorized",
		},
		{
			name:       "404 no body",
			status:     http.StatusNotFound,
			wantStatus: 404,
			wantMsg:    "Not Found",
		},
		{
			name:       "500 not stored",
			status:     http.StatusInternalServerError,
			body:       map[string]any{"status": 500, "error": "not-stored"},
			wantStatus: 500,
			wantMsg:    "not-stored",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.body != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.status)
					json.NewEncoder(w).Encode(tt.body)
				} else {
					w.WriteHeader(tt.status)
				}
			}))
			defer srv.Close()

			ks := testKeyStore(t)
			c := New(ks, WithBaseURL(srv.URL))
			err := c.SubmitSettlement(t.Context(), testSettlementParams())

			apiErr, ok := errors.AsType[*APIError](err)
			if !ok {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", apiErr.StatusCode, tt.wantStatus)
			}
			if apiErr.Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", apiErr.Message, tt.wantMsg)
			}
		})
	}
}
