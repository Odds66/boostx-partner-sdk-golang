package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

	c := New(WithBaseURL(srv.URL))
	err := c.SubmitSettlement(context.Background(), "eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SettlementJWT != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("settlementJWT = %q, want %q", got.SettlementJWT, "eyJhbGciOiJFUzI1NiJ9.test.sig")
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
			name:       "401 unauthorized",
			status:     http.StatusUnauthorized,
			body:       map[string]string{"error": "unauthorized"},
			wantStatus: 401,
			wantMsg:    "unauthorized",
		},
		{
			name:       "404 no body",
			status:     http.StatusNotFound,
			wantStatus: 404,
			wantMsg:    "Not Found",
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

			c := New(WithBaseURL(srv.URL))
			err := c.SubmitSettlement(context.Background(), "some.jwt.token")

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
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

func TestSubmitSettlement_EmptyJWT(t *testing.T) {
	c := New()
	err := c.SubmitSettlement(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "settlementJWT must not be empty" {
		t.Errorf("error = %q, want %q", err.Error(), "settlementJWT must not be empty")
	}
}
