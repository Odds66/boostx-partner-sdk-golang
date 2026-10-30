package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// acceptingServer answers BoostX's acceptance and records each request's path.
func acceptingServer(t *testing.T, paths *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.Path)
		w.Write([]byte(`{"result":{"ok":true}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSubmitSettlement_RequiresAcceptanceBody(t *testing.T) {
	tests := []struct {
		status  int
		body    string
		wantErr bool
	}{
		{http.StatusOK, "", true},
		{http.StatusNoContent, "", true},
		{http.StatusOK, "<html></html>", true},
		{http.StatusOK, `{"error":"boom"}`, true},
		{http.StatusOK, `{"result":{"ok":false}}`, true},
		{http.StatusOK, `{"result":{"ok":"true"}}`, true},
		{http.StatusCreated, `{"result":{"ok":true}}`, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d %s", tt.status, tt.body), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			err := New(testKeyStore(t), WithBaseURL(srv.URL)).SubmitSettlement(t.Context(), testSettlementParams())
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.status || apiErr.Message != "unexpected response" {
				t.Errorf("got %d %q, want %d %q", apiErr.StatusCode, apiErr.Message, tt.status, "unexpected response")
			}
			if !IsRetryable(err) {
				t.Error("IsRetryable = false, want true")
			}
		})
	}
}

func TestSubmitSettlement_BodyReadTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte(`{"result":`))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := New(testKeyStore(t), WithBaseURL(srv.URL), WithHTTPClient(&http.Client{Timeout: 500 * time.Millisecond}))
	err := c.SubmitSettlement(t.Context(), testSettlementParams())
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := errors.AsType[*APIError](err); ok {
		t.Errorf("got APIError %v, want a read error", err)
	}
	if !IsRetryable(err) {
		t.Errorf("IsRetryable(%v) = false, want true", err)
	}
}

func TestSubmitSettlement_DoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d custom=%t", code, custom), func(t *testing.T) {
				var targetHits atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					targetHits.Add(1)
					w.Write([]byte(`{"result":{"ok":true}}`))
				}))
				defer target.Close()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL+r.URL.Path, code)
				}))
				defer srv.Close()

				opts := []Option{WithBaseURL(srv.URL)}
				if custom {
					opts = append(opts, WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
				}
				c := New(testKeyStore(t), opts...)
				err := c.SubmitSettlement(t.Context(), testSettlementParams())

				apiErr, ok := errors.AsType[*APIError](err)
				if !ok || apiErr.StatusCode != code {
					t.Fatalf("got %v, want APIError %d", err, code)
				}
				if n := targetHits.Load(); n != 0 {
					t.Errorf("redirect target saw %d requests, want 0", n)
				}
				if !IsRetryable(err) {
					t.Error("IsRetryable = false, want true")
				}
				if c.httpClient.CheckRedirect != nil {
					t.Error("the caller's http.Client was modified")
				}
			})
		}
	}
}

func TestNew_BaseURLForms(t *testing.T) {
	var paths []string
	srv := acceptingServer(t, &paths)
	for _, base := range []string{
		srv.URL + "//",
		srv.URL + "/api/integration/settlement/",
		srv.URL + "/api/integration/settlement\n",
	} {
		paths = nil
		err := New(testKeyStore(t), WithBaseURL(base)).SubmitSettlement(t.Context(), testSettlementParams())
		if err != nil {
			t.Errorf("%q: unexpected error: %v", base, err)
		}
		if len(paths) != 1 || paths[0] != "/api/integration/settlement" {
			t.Errorf("%q: posted to %q, want [/api/integration/settlement]", base, paths)
		}
	}
}

func TestNew_NilArguments(t *testing.T) {
	t.Run("nil key store panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r != "boostx: nil key store" {
				t.Errorf("recover() = %v, want %q", r, "boostx: nil key store")
			}
		}()
		New(nil)
	})
	t.Run("nil http client keeps the default", func(t *testing.T) {
		var paths []string
		srv := acceptingServer(t, &paths)
		err := New(testKeyStore(t), WithBaseURL(srv.URL), WithHTTPClient(nil)).SubmitSettlement(t.Context(), testSettlementParams())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"400", &APIError{400, "invalid-status"}, false},
		{"403", &APIError{403, "Forbidden"}, false},
		{"404 unknown partner", &APIError{404, "not found"}, false},
		{"404 route", &APIError{404, "Not Found"}, true},
		{"401", &APIError{401, "unauthorized"}, true},
		{"500", &APIError{500, "not-stored"}, true},
		{"503", &APIError{503, "Service Unavailable"}, true},
		{"301", &APIError{301, "Moved Permanently"}, true},
		{"2xx without acceptance", &APIError{200, "unexpected response"}, true},
		{"wrapped 400", fmt.Errorf("x: %w", &APIError{400, "invalid-payout"}), false},
		{"invalid claim", fmt.Errorf("create settlement token: %w", fmt.Errorf("%w: status", tokens.ErrInvalidClaim)), false},
		{"missing claim", fmt.Errorf("create settlement token: %w", fmt.Errorf("%w: partner", tokens.ErrMissingClaim)), false},
		{"unknown partner", fmt.Errorf("resolve settlement key: %w", fmt.Errorf("%w %q", keys.ErrUnknownPartner, "p")), false},
		{"key store failure", errors.New("kms timeout"), true},
		{"context canceled", context.Canceled, true},
		{"read response", fmt.Errorf("read response: %w", context.DeadlineExceeded), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

// keyStoreFunc adapts a function to KeyStore.
type keyStoreFunc func(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)

func (f keyStoreFunc) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	return f(ctx, partner)
}

func TestIsRetryable_SubmitSettlement(t *testing.T) {
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"status":401,"error":"unauthorized"}`))
	}))
	defer unauthorized.Close()
	unreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the settlement was sent")
	}))
	defer unreached.Close()

	kmsDown := keyStoreFunc(func(context.Context, string) (*ecdsa.PrivateKey, error) {
		return nil, errors.New("kms timeout")
	})
	unknownPartner := testSettlementParams()
	unknownPartner.Partner = "partner-2"
	won := testSettlementParams()
	won.Status = "won"

	tests := []struct {
		name   string
		ks     KeyStore
		url    string
		params tokens.SettlementParams
		want   bool
	}{
		{"key store failure", kmsDown, unreached.URL, testSettlementParams(), true},
		{"unknown partner", testKeyStore(t), unreached.URL, unknownPartner, false},
		{"invalid status", testKeyStore(t), unreached.URL, won, false},
		{"401", testKeyStore(t), unauthorized.URL, testSettlementParams(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(tt.ks, WithBaseURL(tt.url)).SubmitSettlement(t.Context(), tt.params)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := IsRetryable(err); got != tt.want {
				t.Errorf("IsRetryable(%v) = %t, want %t", err, got, tt.want)
			}
		})
	}
}
