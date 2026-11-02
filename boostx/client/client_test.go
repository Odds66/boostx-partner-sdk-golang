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
	"strings"
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
			wantMsg:    "HTTP 404",
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

// TestSubmitSettlement_ErrorText pins Message on a refusal: the body's "error"
// by exact name when it is a non-empty string in one JSON object in valid
// UTF-8, otherwise exactly "HTTP <status>".
func TestSubmitSettlement_ErrorText(t *testing.T) {
	for _, tt := range []struct {
		status     int
		body, want string
	}{
		{http.StatusNotFound, "Not Found", "HTTP 404"},
		{http.StatusNotFound, `{"error":"not found"}`, "not found"},
		{http.StatusServiceUnavailable, " {\"error\":\"busy\"}\n", "busy"},
		{http.StatusBadRequest, `{"error":"a","error":"b"}`, "b"},
		{http.StatusBadRequest, `{"error":"a","error":null}`, "HTTP 400"},
		{http.StatusBadRequest, `{"Error":"invalid-version"}`, "HTTP 400"},
		{http.StatusInternalServerError, `{"error":""}`, "HTTP 500"},
		{http.StatusInternalServerError, `{"error":5}`, "HTTP 500"},
		{http.StatusBadRequest, `{"error":"a"} {}`, "HTTP 400"},
		{http.StatusBadRequest, "{\"error\":\"bad\xff\"}", "HTTP 400"},
		{http.StatusBadRequest, "\xef\xbb\xbf{\"error\":\"bom\"}", "HTTP 400"},
		{http.StatusBadGateway, "", "HTTP 502"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.status)
			w.Write([]byte(tt.body))
		}))
		err := New(testKeyStore(t), WithBaseURL(srv.URL)).SubmitSettlement(t.Context(), testSettlementParams())
		srv.Close()
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.StatusCode != tt.status || apiErr.Message != tt.want {
			t.Errorf("%d %q: got %v, want APIError %d %q", tt.status, tt.body, err, tt.status, tt.want)
		}
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

// accepted is BoostX's acceptance body.
const accepted = `{"result":{"ok":true}}`

// TestSubmitSettlement_RequiresAcceptanceBody pins that only a 2xx whose first
// 64 KiB are one JSON object in valid UTF-8, without a byte order mark, with
// "result" and then "ok" true by exact name, the last repeated name winning, is
// an acceptance.
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
		{http.StatusOK, `{"result":{"ok":null}}`, true},
		{http.StatusOK, `null`, true},
		{http.StatusOK, `{"Result":{"OK":true}}`, true},
		{http.StatusOK, `{"result":{"OK":true}}`, true},
		{http.StatusOK, `{"result":{"ok":true},"result":null}`, true},
		{http.StatusOK, `{"result":{"ok":true},"result":{}}`, true},
		{http.StatusOK, `{"result":{"ok":true,"ok":false}}`, true},
		{http.StatusOK, `{"result":{"ok":true}} {}`, true},
		{http.StatusOK, "{\"result\":{\"ok\":true},\"x\":\"\xff\"}", true},
		{http.StatusOK, "\xef\xbb\xbf{\"result\":{\"ok\":true}}", true},
		{http.StatusOK, strings.Repeat(" ", 64<<10-len(accepted)+1) + accepted, true},
		{http.StatusCreated, `{"result":{"ok":true}}`, false},
		{http.StatusOK, `{"result":null,"result":{"ok":true}}`, false},
		{http.StatusOK, " {\"result\":{\"ok\":true,\"x\":1},\"y\":2}\n", false},
		{http.StatusOK, strings.Repeat(" ", 64<<10-len(accepted)) + accepted, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d %.40q", tt.status, tt.body), func(t *testing.T) {
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
}

// TestSubmitSettlement_CancelDuringBodyRead pins that a cancellation while the
// body is read is returned as itself, whatever the status, never an *APIError.
func TestSubmitSettlement_CancelDuringBodyRead(t *testing.T) {
	for _, status := range []int{200, 400, 503} {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(status)
			w.Write([]byte(`{"error":`))
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(150*time.Millisecond, cancel)
		err := New(testKeyStore(t), WithBaseURL(srv.URL)).SubmitSettlement(ctx, testSettlementParams())
		if _, isAPIError := errors.AsType[*APIError](err); isAPIError || !errors.Is(err, context.Canceled) {
			t.Errorf("status %d: expected context.Canceled, got %v", status, err)
		}
		close(release)
		srv.Close()
		cancel()
	}
}

// TestSubmitSettlement_TimeLimitCoversKeyLookup pins that one time limit, the
// http.Client's Timeout or 30 s when it is 0, runs from the key lookup on, and
// that a caller's earlier deadline wins.
func TestSubmitSettlement_TimeLimitCoversKeyLookup(t *testing.T) {
	unreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the settlement was sent")
	}))
	defer unreached.Close()

	var left time.Duration
	recordDeadline := keyStoreFunc(func(ctx context.Context, _ string) (*ecdsa.PrivateKey, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("no deadline")
		}
		left = time.Until(deadline)
		return nil, errors.New("stop here")
	})
	shortCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for name, tc := range map[string]struct {
		ctx      context.Context
		opts     []Option
		min, max time.Duration
	}{
		"default client":         {t.Context(), nil, 29 * time.Second, 30 * time.Second},
		"client without Timeout": {t.Context(), []Option{WithHTTPClient(&http.Client{})}, 29 * time.Second, 30 * time.Second},
		"client Timeout 5 s":     {t.Context(), []Option{WithHTTPClient(&http.Client{Timeout: 5 * time.Second})}, 4 * time.Second, 5 * time.Second},
		"caller deadline 1 s":    {shortCtx, nil, 0, time.Second},
		"nil context":            {nil, nil, 29 * time.Second, 30 * time.Second},
	} {
		left = 0
		err := New(recordDeadline, append(tc.opts, WithBaseURL(unreached.URL))...).SubmitSettlement(tc.ctx, testSettlementParams())
		if err == nil || left <= tc.min || left > tc.max {
			t.Errorf("%s: key lookup saw %v left (err %v), want in (%v, %v]", name, left, err, tc.min, tc.max)
		}
	}

	blocking := keyStoreFunc(func(ctx context.Context, _ string) (*ecdsa.PrivateKey, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, errors.New("the key lookup was not cancelled")
		}
	})
	start := time.Now()
	err := New(blocking, WithBaseURL(unreached.URL), WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond})).
		SubmitSettlement(t.Context(), testSettlementParams())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("a key store that blocks: expected context.DeadlineExceeded after 100 ms, got %v after %v", err, time.Since(start))
	}
}

// keyStoreFunc adapts a function to KeyStore.
type keyStoreFunc func(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)

func (f keyStoreFunc) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	return f(ctx, partner)
}

func TestSubmitSettlement_RefusedBeforeSending(t *testing.T) {
	unreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the settlement was sent")
	}))
	defer unreached.Close()

	errKMS := errors.New("kms timeout")
	kmsDown := keyStoreFunc(func(context.Context, string) (*ecdsa.PrivateKey, error) {
		return nil, errKMS
	})
	unknownPartner := testSettlementParams()
	unknownPartner.Partner = "partner-2"
	noUser := testSettlementParams()
	noUser.User = ""
	won := testSettlementParams()
	won.Status = "won"

	noKey := keyStoreFunc(func(context.Context, string) (*ecdsa.PrivateKey, error) {
		return nil, nil
	})

	tests := []struct {
		name   string
		ks     KeyStore
		params tokens.SettlementParams
		want   error
	}{
		{"key store failure", kmsDown, testSettlementParams(), errKMS},
		{"key store returns no key", noKey, testSettlementParams(), tokens.ErrInvalidPrivateKey},
		{"unknown partner", testKeyStore(t), unknownPartner, keys.ErrUnknownPartner},
		{"missing user", testKeyStore(t), noUser, tokens.ErrMissingClaim},
		{"invalid status", testKeyStore(t), won, tokens.ErrInvalidClaim},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(tt.ks, WithBaseURL(unreached.URL)).SubmitSettlement(t.Context(), tt.params)
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want an error matching %v", err, tt.want)
			}
		})
	}
}

// TestSubmitSettlement_ContextAlreadyDone pins that a done context returns its
// error before the key store is called.
func TestSubmitSettlement_ContextAlreadyDone(t *testing.T) {
	var calls atomic.Int32
	ks := keyStoreFunc(func(context.Context, string) (*ecdsa.PrivateKey, error) {
		calls.Add(1)
		return nil, errors.New("stop here")
	})
	c := New(ks)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if err := c.SubmitSettlement(canceled, testSettlementParams()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: expected context.Canceled, got %v", err)
	}
	if err := c.SubmitSettlement(expired, testSettlementParams()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expired: expected context.DeadlineExceeded, got %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("key store called %d times, want 0", n)
	}
	if err := c.SubmitSettlement(t.Context(), testSettlementParams()); err == nil || calls.Load() != 1 {
		t.Errorf("a live context: expected one key store call, got %d (err %v)", calls.Load(), err)
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
		" \t\r\n\v\f" + srv.URL + "/ \t\r\n\v\f",
		strings.ToUpper(srv.URL),
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

// panicsWith reports whether f panics with want.
func panicsWith(f func(), want string) (ok bool) {
	defer func() { ok = recover() == want }()
	f()
	return false
}

func TestNew_NilArguments(t *testing.T) {
	t.Run("nil key store panics", func(t *testing.T) {
		if !panicsWith(func() { New(nil) }, "boostx: nil key store") {
			t.Error("New(nil): expected panic \"boostx: nil key store\"")
		}
		var nilStore *keys.MemoryKeyStore
		if !panicsWith(func() { New(nilStore) }, "boostx: nil key store") {
			t.Error("New((*MemoryKeyStore)(nil)): expected panic \"boostx: nil key store\"")
		}
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

// TestNew_InvalidBaseURL pins that New panics unless the base URL, after its
// ASCII whitespace, trailing slashes and endpoint path are removed, starts with
// http:// or https:// and has a host; only an absent WithBaseURL selects the default.
func TestNew_InvalidBaseURL(t *testing.T) {
	for _, base := range []string{
		"",
		" \t\r\n",
		"/",
		"partners-s2s.boostx.cloud",
		"ftp://partners-s2s.boostx.cloud",
		"mailto:x",
		"http:/x",
		"https:example.com",
		"https://",
		"https:///api/integration/settlement",
		"https://:443",
		"\ufeffhttps://partners-s2s.boostx.cloud",
		"\u00a0https://partners-s2s.boostx.cloud",
		"\u0085https://partners-s2s.boostx.cloud",
	} {
		if !panicsWith(func() { New(testKeyStore(t), WithBaseURL(base)) }, "boostx: invalid base URL") {
			t.Errorf("%q: expected panic \"boostx: invalid base URL\"", base)
		}
	}
	if c := New(testKeyStore(t)); c.baseURL != DefaultBaseURL {
		t.Errorf("no WithBaseURL: base URL %q, want %q", c.baseURL, DefaultBaseURL)
	}
}

// TestNew_NegativeTimeout pins that New panics on a negative http.Client
// Timeout, while 0 means the 30 s default.
func TestNew_NegativeTimeout(t *testing.T) {
	negative := WithHTTPClient(&http.Client{Timeout: -time.Second})
	if !panicsWith(func() { New(testKeyStore(t), negative) }, "boostx: negative http.Client Timeout") {
		t.Error("expected panic \"boostx: negative http.Client Timeout\"")
	}
	New(testKeyStore(t), WithHTTPClient(&http.Client{}))
}
